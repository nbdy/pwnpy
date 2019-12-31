let mapMarkers = [];

function addMapMarker(lnglat, data) {
    let m = L.marker(lnglat, {"title": data});
    m.bindPopup(data).openPopup();
    m.addTo(map);
    mapMarkers.push(m);
}

function clearMapMarkers(){
    for(let i=0; i<mapMarkers.length; i++){
        map.removeLayer(mapMarkers[i]);
    }
}

function tableChosen(ctx) {
    $.getJSON("/api/columns/" + ctx.innerText, null, function (data) {
        let content = "";
        for(let col in data) {
            content += '<a class="dropdown-item" href="#">' + data[col] + '</a>';
        }
        $('#columnDropdownMenu').html(content);
        $('#columnDropdown').text(data[0]);
        $('#tableDropdown').text(ctx.innerText);
        search();
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

function setPopups(map, rows) {
    clearMapMarkers();
    for(let row in rows){
        for(let pos in rows[row]["positions"]){
            console.log(rows[row]);
            addMapMarker([rows[row]["positions"][pos]["latitude"], rows[row]["positions"][pos]["longitude"]],
                rows[row]["name"] + "\n" + rows[row]["address"]);
        }
    }
}

function search(){
    $.post("/api/search", {"currentPosition": currentPosition, "table": $('#tableDropdown').text(), "filters": [], "radius": "20km", "maxPositions": 10}, success=function (data) {
        buildTable("searchResultTable", data["columns"], data["rows"]);
        setPopups(map, data["rows"]);
    }, "json");
}

function buildMap() {
    let m = L.map('map');
    m.setView(currentPosition, 13);
    L.tileLayer('https://api.tiles.mapbox.com/v4/{id}/{z}/{x}/{y}.png?access_token={accessToken}', {
        attribution: 'Map data &copy; <a href="https://www.openstreetmap.org/">OpenStreetMap</a> contributors, <a href="https://creativecommons.org/licenses/by-sa/2.0/">CC-BY-SA</a>, Imagery © <a href="https://www.mapbox.com/">Mapbox</a>',
        maxZoom: 18,
        id: 'mapbox.streets',
        accessToken: 'pk.eyJ1IjoidHJpZzBuIiwiYSI6ImNpeHJ3bWF3dzA2NGszM281czJhZWF5NGoifQ.w9yuisMiPtwMRv7u0WjgIQ'
    }).addTo(m);
    return m;
}

function updateCounts(){
    let ws = new WebSocket("/api/counts");
    ws.onmessage = function (e) {
        console.log(e.data);
    }
}