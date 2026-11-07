const API_URL = "http://127.0.0.1:8000/scan";

const ipInput = document.getElementById("ip-input");
const scanBtn = document.getElementById("scan-btn");
const resultsDiv = document.getElementById("results");

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
