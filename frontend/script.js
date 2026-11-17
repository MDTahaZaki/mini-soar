const API_URL = "http://127.0.0.1:8000/scan";
const HISTORY_URL = "http://127.0.0.1:8000/history?limit=5";

const ipInput = document.getElementById("ip-input");
const scanBtn = document.getElementById("scan-btn");
const resultsDiv = document.getElementById("results");
const historyBody = document.getElementById("history-body");

// Same thresholds automation.py uses to decide whether to alert.
const VT_ALERT_THRESHOLD = 0;
const ABUSE_ALERT_THRESHOLD = 10;

// SQLite drops timezone info, so the API returns UTC timestamps without a
// "Z". Without it, the browser would treat them as local time.
function formatDate(isoString) {
    const hasZone = /([zZ]|[+-]\d{2}:?\d{2})$/.test(isoString);
    const date = new Date(hasZone ? isoString : isoString + "Z");
    return isNaN(date) ? isoString : date.toLocaleString();
}

function makeCell(value, flagged = false) {
    const td = document.createElement("td");
    // textContent (not innerHTML) so nothing from the API is parsed as HTML.
    td.textContent = value ?? "N/A";
    if (flagged) td.classList.add("flagged");
    return td;
}

function showHistoryMessage(message) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 4;
    td.className = "empty";
    td.textContent = message;
    tr.appendChild(td);
    historyBody.replaceChildren(tr);
}

async function fetchHistory() {
    const tbody = document.getElementById("history-body");
    tbody.innerHTML = "";

    try {
        const response = await fetch(HISTORY_URL);
        if (!response.ok) {
            throw new Error(`Server returned ${response.status}`);
        }

        const data = await response.json();
        console.log(data);

        if (data.length === 0) {
            showHistoryMessage("No scans yet.");
            return;
        }

        for (const item of data) {
            const tr = document.createElement("tr");
            tr.appendChild(makeCell(item.ip_address));
            tr.appendChild(makeCell(item.vt_malicious, item.vt_malicious > VT_ALERT_THRESHOLD));
            tr.appendChild(makeCell(item.abuse_score, item.abuse_score > ABUSE_ALERT_THRESHOLD));
            tr.appendChild(makeCell(formatDate(item.scanned_at)));
            tbody.appendChild(tr);
        }
    } catch (error) {
        showHistoryMessage(`Could not load history: ${error.message}`);
    }
}

async function scanIP(event) {
    // The button is a form submit button; stop the page from reloading.
    event.preventDefault();

    const ip = ipInput.value.trim();
    if (!ip) {
        alert("Please enter an IP address.");
        return;
    }

    scanBtn.disabled = true;
    scanBtn.textContent = "Scanning...";

    try {
        const response = await fetch(API_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip: ip }),
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
    } catch (error) {
        // Network failures (API not running, CORS) land here too.
        alert(`Scan failed: ${error.message}`);
    } finally {
        scanBtn.disabled = false;
        scanBtn.textContent = "Scan";
    }
}

// Pressing Enter in the input also fires a click on the submit button.
scanBtn.addEventListener("click", scanIP);

// Load recent scans as soon as the page opens.
document.addEventListener("DOMContentLoaded", fetchHistory);
