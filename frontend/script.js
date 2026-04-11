async function loadData() {
    const res = await fetch("/logs");
    const data = await res.json();

    const table = document.getElementById("table");

    // clear table
    table.innerHTML = `
        <tr>
            <th>Domain</th>
            <th>Result</th>
        </tr>
    `;

    data.forEach(item => {
        let row = table.insertRow();

        let domainCell = row.insertCell(0);
        let resultCell = row.insertCell(1);

        domainCell.innerText = item.domain;
        resultCell.innerText = item.result;

        // color coding
        if (item.result === "Malicious") {
            resultCell.style.color = "red";
        } else {
            resultCell.style.color = "lightgreen";
        }
    });
}

// auto refresh every 3 sec
setInterval(loadData, 3000);

// initial load
loadData();