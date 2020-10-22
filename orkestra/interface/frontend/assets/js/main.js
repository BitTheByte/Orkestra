var config = {
  tree: $(".treeview"),
  breakPointColor: "rgba(255, 0, 0, 0.8)",
  breakPointerHoverColor: "red"
}

function makeRequest(url, callback){
  $.get({url: url, success: callback, async: false})
}


function toggleAttachBtn(element, package){
  makeRequest(`/debugger/status`, function(status){
      if (status.attached) {
        element.innerText = "Detach"
        element.classList.add("btn-danger")
        element.classList.remove("btn-info")
        element.onclick = _ => detach(element, package)
      } else {
        element.innerText = "Attach"
        element.classList.remove("btn-danger")
        element.classList.add("btn-info")
        element.onclick = _ => attach(element, package) 
      }
  })
}

function detach(element, package){
  makeRequest(`/debugger/${package}/detach`, function(){
    toggleAttachBtn(element, package)
  })
}

function attach(element, package) {
  makeRequest(`/debugger/${package}/attach`, function(){
    toggleAttachBtn(element, package)
  })
}

function spawn(element, package){
  makeRequest(`/debugger/${package}/spawn`, function(){
    toggleAttachBtn(element, package)
  })
}


function initTree(url){
  var tree = {
    "core":{
      "themes": {
          "icons": true,
          "responsive": true
        },
      "data": {
        "url": url,
        "data": node => { return { "children": node.children, "text": node.name} }
      },
    },
    'plugins' : [ "types" ],
    'types' : {
      'default' : {
          'icon' : 'fa fa-folder fa-fw'
      },
      'f-open' : {
          'icon' : 'fa fa-folder-open fa-fw'
      },
      'f-closed' : {
          'icon' : 'fa fa-folder fa-fw'
      }
    }
  }

  config.tree.on('open_node.jstree', function(e, data){
      var icon = $('#' + data.node.id).find('i.jstree-icon.jstree-themeicon').first();
      icon.removeClass('fa-folder').addClass('fa-folder-open');
  });

  config.tree.on('close_node.jstree', function(e, data){
      var icon = $('#' + data.node.id).find('i.jstree-icon.jstree-themeicon').first();
      icon.removeClass('fa-folder-open').addClass('fa-folder');
  });
  config.tree.jstree(tree)

}


function include(selector, url) {
  $(selector).load(url);
}
  


function rmbreakpoint(obj, line) {
  makeRequest(`/breakpoint/${workFile.value}/${line}/remove`, function(status){
    if (status.removed)
      colorLine(obj, line, '')
      RemoveBreakPointData(document.getElementById("breakpoint-table"), line)
      obj.setAttribute("breakpoint", false);
  })
}


function breakpoint(obj, line, fake) {
  if(obj.getAttribute("breakpoint") == "true"){return}
    
    var bp = (status) => {
      if (status.added) {
        colorLine(obj, line, 'red')
        insertBreakPointData(document.getElementById("breakpoint-table"), [status.line, status.class, status.method])
        obj.setAttribute("breakpoint", true);
      }
    }

    if (fake)
      return bp({added: true,line: fake.line,class: fake.class, method: fake.method})
    makeRequest(`/breakpoint/${workFile.value}/${line}`, bp)
}


function colorLine (obj, line, color){
  hljs.initHighlightLinesOnLoad([
    [{
      start: line,
      end: line,
      color: color
    }]
  ]);
}


function styleCode(selector) {
    document.querySelectorAll(selector).forEach((block) => {
      hljs.lineNumbersBlock(block);
      hljs.highlightBlock(block);
    })

    waitForEl(".hljs-ln-numbers", function () {

      for (var codeline of document.getElementsByClassName("hljs-ln-line hljs-ln-numbers")) {

        var linenumber = parseInt(codeline.getAttribute("data-line-number"));

        for (bprow of workBP.value.split(",")) {
          let [bpline, bpclass, bpmethod] = bprow.split("/")
          bpline = parseInt(bpline)
          if ((linenumber - 1) == bpline)
            breakpoint(codeline, bpline, {line: bpline, class: bpclass, method: bpmethod})
        }

        codeline.onclick  = function (element, linenumber) {
          return _=> {element.getAttribute("breakpoint") == "true"? rmbreakpoint(element, linenumber - 1) : breakpoint(element, linenumber - 1)}
        }(codeline, linenumber)

        codeline.onmouseover  = function (element) {
          return _=> {element.style.color = "red"}
        }(codeline)

        codeline.onmouseleave  = function (element) {
          return _=> {element.style.color = ""}
        }(codeline)
      }
    })
}

include('.top', "/views/top.html");
include('.console', "/views/console.html")
include('.models', "/views/models.html");

$(document).ready(function () {
  var url = new URL(window.location.href);
  var target = url.searchParams.get("apk");

  if (target == "" || target == undefined || target == null){
    return
  }


  initTree(`apk/${target}/tree`)

  config.tree.on("select_node.jstree", function (e, data) {
    var parentPath = [];
    var selected = data.node

    parentPath.push(getNodeName(selected.id))

    for (node of selected.parents) {
      var name = getNodeName(node)
      if (name != undefined)
        parentPath.push(name)
    }

    parentPath = parentPath.reverse().join("/")

    makeRequest(`/apk/${target}/files/${parentPath}`, function(body){
      $('.preview .code').html(body)
      styleCode('.preview pre code')
    })
  })
  

  setInterval(function(){
    makeRequest("/debugger/sync", function(response){
      if (response.message != undefined) {
        insertTableData(document.getElementById("output-table"), response)
      }
    })
  }, 500)
  
});