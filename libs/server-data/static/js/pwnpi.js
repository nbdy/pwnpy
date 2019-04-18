function tableChosen(ctx) {
    $.getJSON("/api/columns/" + $('#tableDropdown').text(), null, function (data) {
        console.log(data);
    });
}