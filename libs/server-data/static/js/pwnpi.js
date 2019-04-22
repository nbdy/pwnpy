function tableChosen(ctx) {
    $.getJSON("/api/columns/" + $('#tableDropdown').text(), null, function (data) {
        console.log(data);
    });
}

function buildTable(divId, keys, rows) {
    let tableData = '<table class="table">';
    tableData += '<thead><tr><th scope="col">#</th>';
    for(let key in keys) tableData += '<th scope="col">' + keys[key] + '</th>';
    tableData += '</tr></thead><tbody>';
    let i = 0;
    for(let row in rows) {
        tableData += "<tr>";
        tableData += '<th scope="row">' + i + "</th>";
        for(let key in keys){
            if(keys[key] == "positions"){
                tableData += '<td>' + rows[row][keys[key]].length + '</td>';
            } else {
                tableData += '<td>' + rows[row][keys[key]] + '</td>';
            }
        }
        tableData += "</tr>";
        i++;
    }
    tableData += "</tbody></table>";
    $('#' + divId).html(tableData);
}

function setMarkers(map, rows) {
    let m;
    for(let row in rows){
        for(let pos in rows[row]["positions"]){
            console.log(rows[row]);
            m = L.marker([rows[row]["positions"][pos]["latitude"], rows[row]["positions"][pos]["longitude"]], {
                "title": rows[row]["name"] + "\n" + rows[row]["address"]
            });
            m.addTo(map);
        }
    }
}