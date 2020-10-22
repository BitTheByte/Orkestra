var waitForEl = function(selector, callback) {
    if (jQuery(selector).length) {
        callback();
    } else {
        setTimeout(function() {
            waitForEl(selector, callback);
        }, 1000);
    }
};

function getNodeName(nodeId){
    if (nodeId == "#"){
        return undefined
    }
    return document.getElementById(nodeId + "_anchor").text
}

function insertBreakPointData(element, data){
    var row = element.getElementsByTagName('tbody')[0].insertRow();
    row.insertCell().outerHTML = `<td scope='row'>${element.rows.length - 1}</td>`

    for(var i=1; i <= data.length; i++){
        var cell = row.insertCell(i);
        cell.innerText = data[i - 1];
    }
}

function RemoveBreakPointData(element, on_line){
    for(var i=1; i < element.rows.length; i++){
        element.rows[i].cells[0].innerText = i

        var number = parseInt(element.rows[i].innerText.split("\t")[0])
        var line   = parseInt(element.rows[i].innerText.split("\t")[1])
        console.log(on_line, number , line)
        if (line == on_line){
            element.deleteRow(number)
        }
    }
}

function insertTableData(element, data){
    var row = element.getElementsByTagName('tbody')[0].insertRow();

    if (data.from == "jmethod"){
        if(data.message.type == "send"){
            var cell = row.insertCell()
            var html = "<tr><td>"
            html += `<span style="color:green;font-weight:bold";>${data.message.type.toUpperCase()}</span>   `
            html += `Method: ${data.message.payload.name}(${data.message.payload.args.join(',')})`
            html += " -> "
            html += data.message.payload.retval
            html += "</td></tr>"
            cell.outerHTML = html
        }

        if (data.message.type == "error"){
            var cell = row.insertCell()
            var html = "<tr><td>"
            html += `<span style="color:red;font-weight:bold";>${data.message.type.toUpperCase()}</span>   `
            html += data.message.description
            html += "</td></tr>"
            cell.outerHTML = html
        }
    }
}

function toggleConsole(element){
    var app = document.getElementsByClassName("app")[0];
    var console = document.getElementsByClassName("console")[0];
    if(console.hidden){
        console.hidden = false
        element.innerText = "Hide Console"
        app.style.gridTemplateRows = "62px 1fr 250px"
    }else{
        console.hidden = true
        element.innerText = "Show Console"
        app.style.gridTemplateRows = "62px 1fr"
    }
}