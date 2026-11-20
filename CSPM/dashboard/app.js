
const API = "http://127.0.0.1:8000";

function el(id) {
    return document.getElementById(id);
}

function setStatus(id, message) {
    const element = el(id);
    if (element) element.textContent = message;
}

async function fetchJSON(path, options = {}) {
    let response;

    try {
        response = await fetch(`${API}${path}`, options);
    } catch (error) {
        throw new Error(
            `Cannot connect to the API at ${API}. Check FastAPI and CORS settings. ${error.message}`
        );
    }

    if (!response.ok) {
        const detail = await response.text();
        throw new Error(
            `HTTP ${response.status} at ${path}: ${detail}`
        );
    }

    return response.json();
}

function renderRows(id, items, fields) {
    const tbody = el(id);
    if (!tbody) return;

    tbody.replaceChildren();

    for (const item of items) {
        const tr = document.createElement("tr");

        for (const field of fields) {
            const td = document.createElement("td");
            const value = typeof field.value === "function"
                ? field.value(item)
                : item[field.key];

            td.textContent = value ?? "Not available";
            tr.appendChild(td);
        }

        tbody.appendChild(tr);
    }
}

// 1. Dashboard overview, assets, findings, and events.
async function loadDashboard() {
    setStatus("message", "Loading CSPM data...");

    try {
        const [assets, findings, events] = await Promise.all([
            fetchJSON("/assets"),
            fetchJSON("/findings"),
            fetchJSON("/events")
        ]);

        if (
            !Array.isArray(assets) ||
            !Array.isArray(findings) ||
            !Array.isArray(events)
        ) {
            throw new Error("An API endpoint returned an unexpected data format.");
        }

        if (el("assetCount")) {
            el("assetCount").textContent = assets.length;
        }

        if (el("findingCount")) {
            el("findingCount").textContent = findings.length;
        }

        if (el("criticalCount")) {
            el("criticalCount").textContent = findings.filter(
                item =>
                    String(item.risk_level || "").toUpperCase() === "CRITICAL"
            ).length;
        }

        if (el("eventCount")) {
            el("eventCount").textContent = events.length;
        }

        renderRows("assetRows", assets, [
            { key: "asset_id" },
            { value: item => item.asset_type ?? item.type },
            { key: "category" }
        ]);

        renderRows("findingRows", findings, [
            { key: "asset_id" },
            { key: "issue" },
            { key: "severity" },
            { key: "risk_score" },
            { key: "risk_level" }
        ]);

        const eventList = el("eventList");

        if (eventList) {
            eventList.replaceChildren();

            if (events.length === 0) {
                eventList.textContent = "No security events found.";
            } else {
                for (const event of events.slice(0, 10)) {
                    const p = document.createElement("p");
                    const strong = document.createElement("strong");

                    strong.textContent =
                        event.event_type ?? event.event ?? "Security event";

                    p.append(
                        strong,
                        document.createTextNode(
                            ` - ${event.asset_id ?? "Unknown asset"}`
                        )
                    );

                    eventList.appendChild(p);
                }
            }
        }

        setStatus("message", "Dashboard data updated successfully.");
    } catch (error) {
        setStatus("message", `Dashboard error: ${error.message}`);
        console.error("Dashboard error:", error);
    }
}

// 2. Attack graph.
async function loadAttackGraph() {
    setStatus("graphStatus", "Loading attack graph...");

    const container = el("attackGraph");
    const resultsContainer = el("graphPathResults");

    if (resultsContainer) resultsContainer.replaceChildren();

    try {
        if (typeof vis === "undefined") {
            throw new Error("vis-network did not load. Check your internet connection.");
        }

        const data = await fetchJSON("/attack-path");

        if (!Array.isArray(data.nodes) || !Array.isArray(data.edges)) {
            throw new Error("The API must return nodes and edges arrays.");
        }

        const paths = Array.isArray(data.paths) ? data.paths : [];
        const riskyAssets = new Set();

        for (const path of paths) {
            for (const finding of path.findings || []) {
                const risk = String(
                    finding.risk_level || finding.severity || ""
                ).toUpperCase();

                if (["CRITICAL", "VERY HIGH", "HIGH"].includes(risk)) {
                    riskyAssets.add(finding.asset_id);
                }
            }
        }

        const nodes = new vis.DataSet(data.nodes.map(node => {
            const id = typeof node === "object"
                ? (node.id ?? node.asset_id)
                : node;

            const label = typeof node === "object"
                ? (node.label ?? id)
                : node;

            const risky = riskyAssets.has(id);
            const internet = String(id).toLowerCase() === "internet";

            return {
                id,
                label: String(label),
                shape: "box",
                margin: 12,
                color: {
                    background: internet
                        ? "#343b36"
                        : risky
                            ? "#512c2c"
                            : "#263c2c",
                    border: internet
                        ? "#9ca3af"
                        : risky
                            ? "#ef7777"
                            : "#75ad82"
                },
                font: { color: "#f1f5f2", size: 15 },
                borderWidth: risky ? 3 : 1,
                title: risky
                    ? "High-risk asset: review findings"
                    : String(label)
            };
        }));

        const edges = new vis.DataSet(data.edges.map((edge, index) => {
            const from = edge.from ?? edge.source;
            const to = edge.to ?? edge.target;

            const path = paths.find(item => {
                if (!Array.isArray(item.path)) return false;
                const position = item.path.indexOf(from);
                return position >= 0 && item.path[position + 1] === to;
            });

            const risk = String(path?.risk_level || "").toUpperCase();

            return {
                id: edge.id ?? index,
                from,
                to,
                arrows: "to",
                color: {
                    color: ["CRITICAL", "VERY HIGH"].includes(risk)
                        ? "#ef7777"
                        : risk === "HIGH"
                            ? "#e8a34c"
                            : "#91a899"
                },
                width: risk === "CRITICAL" ? 3 : 2
            };
        }));

        if (!container) {
            throw new Error("The attackGraph element is missing from index.html.");
        }

        if (container.cspmNetwork) {
            container.cspmNetwork.destroy();
        }

        container.cspmNetwork = new vis.Network(
            container,
            { nodes, edges },
            {
                autoResize: true,
                physics: {
                    enabled: true,
                    stabilization: { iterations: 150 }
                },
                interaction: {
                    hover: true,
                    navigationButtons: true,
                    keyboard: true
                },
                layout: { improvedLayout: true }
            }
        );

        if (resultsContainer) {
            if (paths.length === 0) {
                resultsContainer.textContent = "No attack paths returned.";
            } else {
                for (const item of paths) {
                    const card = document.createElement("div");
                    card.className = "graph-path-card";

                    const heading = document.createElement("h4");
                    heading.textContent = `Target: ${item.target ?? "Unknown"}`;

                    const pathText = document.createElement("p");
                    pathText.textContent = Array.isArray(item.path)
                        ? item.path.join(" → ")
                        : "Path unavailable";

                    const riskText = document.createElement("p");
                    riskText.textContent =
                        `Risk: ${item.risk_level ?? "Unknown"}; ` +
                        `score: ${item.risk_score ?? "N/A"}`;

                    card.append(heading, pathText, riskText);
                    resultsContainer.appendChild(card);
                }
            }
        }

        setStatus(
            "graphStatus",
            `Graph loaded: ${data.nodes.length} nodes and ${data.edges.length} edges.`
        );
    } catch (error) {
        setStatus("graphStatus", `Graph error: ${error.message}`);
        console.error("Attack graph error:", error);
    }
}

// 3. Remediation recommendations.
async function loadRemediations() {
    setStatus("remediationStatus", "Loading recommendations...");

    try {
        const data = await fetchJSON("/remediations");

        if (!Array.isArray(data)) {
            throw new Error("The remediation endpoint did not return a list.");
        }

        renderRows("remediationRows", data, [
            { key: "asset_id" },
            { key: "issue" },
            {
                value: item =>
                    item.risk_level ?? item.risk_score ?? "Not available"
            },
            { key: "remediation_priority" },
            { key: "recommended_action" }
        ]);

        setStatus(
            "remediationStatus",
            `Loaded ${data.length} recommendations.`
        );
    } catch (error) {
        setStatus(
            "remediationStatus",
            `Remediation error: ${error.message}`
        );
        console.error("Remediation error:", error);
    }
}

// 4. Load saved compliance results.
async function loadComplianceResults() {
    setStatus("complianceStatus", "Loading compliance results...");

    try {
        const results = await fetchJSON("/compliance");

        if (!Array.isArray(results)) {
            throw new Error("The compliance endpoint did not return a list.");
        }

        const count = status => results.filter(
            item => String(item.status || "").toUpperCase() === status
        ).length;

        if (el("totalCompliance")) {
            el("totalCompliance").textContent = results.length;
        }

        if (el("failedCompliance")) {
            el("failedCompliance").textContent = count("FAIL");
        }

        if (el("passedCompliance")) {
            el("passedCompliance").textContent = count("PASS");
        }

        if (el("reviewCompliance")) {
            el("reviewCompliance").textContent = count("REVIEW");
        }

        renderRows("complianceRows", results, [
            { key: "asset_id" },
            { key: "issue" },
            { key: "severity" },
            { key: "framework" },
            { key: "control_id" },
            { key: "control_name" },
            { key: "status" }
        ]);

        setStatus(
            "complianceStatus",
            results.length
                ? `Loaded ${results.length} compliance results.`
                : "No saved compliance results. Run analysis first."
        );
    } catch (error) {
        setStatus(
            "complianceStatus",
            `Could not load compliance results: ${error.message}`
        );
        console.error("Compliance results error:", error);
    }
}

// 5. Run compliance analysis.

async function runComplianceAnalysis() {
    const button = document.getElementById("runComplianceAnalysis");
    const status = document.getElementById("complianceStatus");

    if (button) button.disabled = true;

    if (status) {
        status.textContent = "Running compliance analysis...";
    }

    try {
        const response = await fetch(`${API}/compliance/analyze`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({})
        });

        if (!response.ok) {
            const detail = await response.text();
            throw new Error(`HTTP ${response.status}: ${detail}`);
        }

        const result = await response.json();

        console.log("Compliance analysis response:", result);

        // Use the 12 records returned directly by the analysis API.
        let results = Array.isArray(result.results)
            ? result.results
            : null;

        // If the API didn't include records, retrieve saved results.
        if (!results) {
            const savedResponse = await fetch(`${API}/compliance`);

            if (!savedResponse.ok) {
                throw new Error(
                    `Analysis succeeded, but loading saved results failed: HTTP ${savedResponse.status}`
                );
            }

            const savedData = await savedResponse.json();

            results = Array.isArray(savedData)
                ? savedData
                : Array.isArray(savedData.results)
                    ? savedData.results
                    : null;
        }

        if (!results) {
            throw new Error("The API did not return a compliance results array.");
        }

        // Update the compliance summary cards.
        const count = value => results.filter(item =>
            String(item.status || "").toUpperCase() === value
        ).length;

        if (document.getElementById("totalCompliance")) {
            document.getElementById("totalCompliance").textContent =
                results.length;
        }

        if (document.getElementById("failedCompliance")) {
            document.getElementById("failedCompliance").textContent =
                count("FAIL");
        }

        if (document.getElementById("passedCompliance")) {
            document.getElementById("passedCompliance").textContent =
                count("PASS");
        }

        if (document.getElementById("reviewCompliance")) {
            document.getElementById("reviewCompliance").textContent =
                count("REVIEW");
        }

        // Render the compliance table.
        const tbody = document.getElementById("complianceRows");

        if (!tbody) {
            throw new Error("Element #complianceRows is missing from index.html.");
        }

        tbody.replaceChildren();

        for (const item of results) {
            const row = document.createElement("tr");

            const values = [
                item.asset_id,
                item.issue,
                item.severity,
                item.framework,
                item.control_id,
                item.control_name,
                item.status
            ];

            for (const value of values) {
                const cell = document.createElement("td");
                cell.textContent = value ?? "Not available";
                row.appendChild(cell);
            }

            tbody.appendChild(row);
        }

        if (status) {
            status.textContent =
                `Analysis complete. ${result.findings_analyzed ?? "?"} findings analyzed; ` +
                `${results.length} compliance results displayed.`;
        }

        // Bring the results into view.
        document.getElementById("compliance")?.scrollIntoView({
            behavior: "smooth",
            block: "start"
        });

    } catch (error) {
        if (status) {
            status.textContent =
                `Compliance analysis failed: ${error.message}`;
        }

        console.error("Compliance analysis error:", error);
    } finally {
        if (button) button.disabled = false;
    }
}


// 6. Register each button exactly once.
function initializeDashboard() {
    console.log("CSPM dashboard JavaScript loaded.");

    const bindClick = (id, handler) => {
        const button = el(id);

        if (!button) {
            console.warn(`Button not found: #${id}`);
            return;
        }

        button.addEventListener("click", handler);
    };

    bindClick("refreshBtn", loadDashboard);
    bindClick("loadAttackPath", loadAttackGraph);
    bindClick("loadRemediations", loadRemediations);
    bindClick("loadCompliance", loadComplianceResults);
    bindClick("runComplianceAnalysis", runComplianceAnalysis);

    console.log(
        "Analysis button found:",
        Boolean(el("runComplianceAnalysis"))
    );

    loadDashboard();
}

if (document.readyState === "loading") {
    document.addEventListener(
        "DOMContentLoaded",
        initializeDashboard,
        { once: true }
    );
} else {
    initializeDashboard();
}
