const API_BASE = "http://127.0.0.1:8000";
const HISTORY_URL = `${API_BASE}/history?limit=5`;
// CSV export pulls up to the API's max (le=100 in main.py), not just the table's 5.
const EXPORT_URL = `${API_BASE}/history?limit=100`;
const ANALYTICS_URL = `${API_BASE}/analytics`;

// Per indicator type: endpoint, JSON body key, and input placeholder.
const SCAN_TYPES = {
    ip: {
        url: `${API_BASE}/scan`,
        key: "ip",
        label: "IP address",
        placeholder: "enter IP address, e.g. 8.8.8.8",
    },
    hash: {
        url: `${API_BASE}/scan/hash`,
        key: "hash",
        label: "file hash",
        placeholder: "enter MD5 / SHA1 / SHA256 hash",
    },
};

const scanTypeSelect = document.getElementById("scan-type");
const indicatorInput = document.getElementById("indicator-input");
const scanBtn = document.getElementById("scan-btn");
const resultsDiv = document.getElementById("results");
const historyBody = document.getElementById("history-body");
const downloadBtn = document.getElementById("download-btn");

// Same rule automation.py uses to send a Discord alert
// (VT_THRESHOLD / ABUSE_THRESHOLD there) — keep the two in sync.
const VT_ALERT_THRESHOLD = 3; // flag if VT malicious count >= this
const ABUSE_ALERT_THRESHOLD = 10; // flag if AbuseIPDB score >= this

function isAlert(item) {
    return (item.vt_malicious ?? 0) >= VT_ALERT_THRESHOLD
        || (item.abuse_score ?? 0) >= ABUSE_ALERT_THRESHOLD;
}

// SQLite drops timezone info, so the API returns UTC timestamps without a
// "Z". Without it, the browser would treat them as local time.
function formatDate(isoString) {
    const hasZone = /([zZ]|[+-]\d{2}:?\d{2})$/.test(isoString);
    const date = new Date(hasZone ? isoString : isoString + "Z");
    return isNaN(date) ? isoString : date.toLocaleString();
}

function makeCell(value) {
    const td = document.createElement("td");
    // textContent (not innerHTML) so nothing from the API is parsed as HTML.
    td.textContent = value ?? "N/A";
    return td;
}

function shortenHash(hash) {
    return hash.length > 20 ? `${hash.slice(0, 10)}…${hash.slice(-8)}` : hash;
}

function showHistoryMessage(message) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 5;
    td.className = "empty";
    td.textContent = message;
    tr.appendChild(td);
    historyBody.replaceChildren(tr);
}

async function fetchHistory() {
    const tbody = document.getElementById("history-body");
    tbody.innerHTML = "";
    downloadBtn.disabled = true;

    try {
        const response = await fetch(HISTORY_URL);
        if (!response.ok) {
            throw new Error(`Server returned ${response.status}`);
        }

        const data = await response.json();
        console.log(data);

        // Nothing to export until at least one scan exists.
        downloadBtn.disabled = data.length === 0;

        if (data.length === 0) {
            showHistoryMessage("No scans yet.");
            return;
        }

        for (const item of data) {
            const tr = document.createElement("tr");
            // A row is either an IP scan (ip_address set) or a hash scan
            // (hash_value set, ip_address null).
            const isHash = !item.ip_address && !!item.hash_value;

            const typeCell = makeCell(isHash ? "Hash" : "IP");
            typeCell.classList.add("type");
            tr.appendChild(typeCell);

            if (isHash) {
                // Full SHA256 is 64 chars; shorten it, keep the full value on hover.
                const indicatorCell = makeCell(shortenHash(item.hash_value));
                indicatorCell.title = item.hash_value;
                tr.appendChild(indicatorCell);
            } else {
                tr.appendChild(makeCell(item.ip_address));
            }

            tr.appendChild(makeCell(item.vt_malicious));
            // AbuseIPDB only checks IPs, so the score doesn't apply to hashes.
            tr.appendChild(makeCell(isHash ? "—" : item.abuse_score));

            // Whole row goes red when the scan would have triggered an alert.
            if (isAlert(item)) tr.classList.add("flagged");
            tr.appendChild(makeCell(formatDate(item.scanned_at)));
            tbody.appendChild(tr);
        }
    } catch (error) {
        showHistoryMessage(`Could not load history: ${error.message}`);
    }
}

// Quote every field and double any quotes inside it (RFC 4180). A leading
// ' stops spreadsheet apps from running a value that starts like a formula.
function toCsvField(value) {
    let text = value == null ? "" : String(value);
    if (/^[=+\-@\t\r]/.test(text)) text = "'" + text;
    return `"${text.replace(/"/g, '""')}"`;
}

async function downloadHistory() {
    downloadBtn.disabled = true;
    downloadBtn.textContent = "Exporting...";

    try {
        const response = await fetch(EXPORT_URL);
        if (!response.ok) {
            throw new Error(`Server returned ${response.status}`);
        }
        const rows = await response.json();
        if (rows.length === 0) {
            alert("No scans to export.");
            return;
        }
        saveCsv(rows);
    } catch (error) {
        alert(`Download failed: ${error.message}`);
    } finally {
        downloadBtn.disabled = false;
        downloadBtn.textContent = "Download History";
    }
}

// Builds the CSV from raw /history rows (full hashes, UTC timestamps)
// and saves it as mini_soar_history.csv.
function saveCsv(rows) {
    const header = ["Type", "Indicator", "VT Malicious", "Abuse Score", "Scanned At (UTC)"];
    const lines = [header.map(toCsvField).join(",")];
    for (const item of rows) {
        const isHash = !item.ip_address && !!item.hash_value;
        lines.push([
            isHash ? "Hash" : "IP",
            isHash ? item.hash_value : item.ip_address,
            item.vt_malicious,
            isHash ? "" : item.abuse_score,
            item.scanned_at,
        ].map(toCsvField).join(","));
    }

    const blob = new Blob([lines.join("\r\n") + "\r\n"], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "mini_soar_history.csv";
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
}

// Chart instances, kept so later calls update them instead of stacking
// a new chart on the same canvas.
let threatChart = null;
let typeChart = null;

function chartColors() {
    const css = getComputedStyle(document.documentElement);
    const v = (name) => css.getPropertyValue(name).trim();
    return { green: v("--green"), greenDim: v("--green-dim"), blue: v("--blue"), red: v("--red"), font: v("--font") };
}

function renderCharts(stats) {
    const c = chartColors();
    Chart.defaults.color = c.green;
    Chart.defaults.font.family = c.font;

    const threatData = [stats.malicious_scans, stats.clean_scans];
    const typeData = [stats.ip_scans, stats.hash_scans];

    if (threatChart) {
        threatChart.data.datasets[0].data = threatData;
        threatChart.update();
    } else {
        threatChart = new Chart(document.getElementById("threatChart"), {
            type: "doughnut",
            data: {
                labels: ["Malicious", "Clean"],
                datasets: [{
                    data: threatData,
                    backgroundColor: [c.red, c.green],
                    borderColor: "#000",
                    borderWidth: 2,
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: "bottom" } },
            },
        });
    }

    if (typeChart) {
        typeChart.data.datasets[0].data = typeData;
        typeChart.update();
    } else {
        typeChart = new Chart(document.getElementById("typeChart"), {
            type: "bar",
            data: {
                labels: ["IP", "Hash"],
                datasets: [{
                    label: "Scans",
                    data: typeData,
                    backgroundColor: [c.blue, c.green],
                }],
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { grid: { color: c.greenDim } },
                    // Counts are whole numbers, so no 0.5 ticks.
                    y: { beginAtZero: true, ticks: { precision: 0 }, grid: { color: c.greenDim } },
                },
            },
        });
    }
}

async function fetchAnalytics() {
    const errorEl = document.getElementById("analytics-error");
    try {
        if (typeof Chart === "undefined") {
            throw new Error("Chart.js failed to load (check your connection to the CDN)");
        }
        const response = await fetch(ANALYTICS_URL);
        if (!response.ok) {
            throw new Error(`Server returned ${response.status}`);
        }
        renderCharts(await response.json());
        errorEl.classList.add("hidden");
    } catch (error) {
        errorEl.textContent = `Could not load analytics: ${error.message}`;
        errorEl.classList.remove("hidden");
    }
}

async function scanIndicator(event) {
    // The button is a form submit button; stop the page from reloading.
    event.preventDefault();

    const scanType = SCAN_TYPES[scanTypeSelect.value];
    const value = indicatorInput.value.trim();
    if (!value) {
        alert(`Please enter a ${scanType.label}.`);
        return;
    }

    scanBtn.disabled = true;
    scanBtn.textContent = "Scanning...";

    try {
        // Body is {"ip": value} for /scan or {"hash": value} for /scan/hash.
        const response = await fetch(scanType.url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ [scanType.key]: value }),
        });

        const data = await response.json();

        if (!response.ok) {
            // FastAPI errors look like {"detail": "..."} (or a list for 422s)
            const detail = typeof data.detail === "string"
                ? data.detail
                : JSON.stringify(data.detail);
            throw new Error(`Server returned ${response.status}: ${detail}`);
        }

        resultsDiv.textContent = JSON.stringify(data, null, 2);
        resultsDiv.classList.remove("hidden");

        // The backend saved this scan, so refresh the table to include it.
        fetchHistory();
        fetchAnalytics();
    } catch (error) {
        // Network failures (API not running, CORS) land here too.
        alert(`Scan failed: ${error.message}`);
    } finally {
        scanBtn.disabled = false;
        scanBtn.textContent = "Scan";
    }
}

// Pressing Enter in the input also fires a click on the submit button.
scanBtn.addEventListener("click", scanIndicator);

downloadBtn.addEventListener("click", downloadHistory);

// Swap the placeholder to match the selected indicator type.
scanTypeSelect.addEventListener("change", () => {
    indicatorInput.placeholder = SCAN_TYPES[scanTypeSelect.value].placeholder;
    indicatorInput.focus();
});

// Load recent scans and charts as soon as the page opens.
document.addEventListener("DOMContentLoaded", () => {
    fetchHistory();
    fetchAnalytics();
});
