function extractShellCommand(shellBlock) {
  var blockLines = shellBlock.innerText.split("\n");
  var command = "";

  var includeNextLine = true;

  for(var j = 0; j < blockLines.length; j++) {
    var line = blockLines[j].trim();

    var cmdStart = line.startsWith("$ ");
    var lineBegin = (cmdStart ? 2 : 0);

    var lineBroken = (line.slice(-1) == "\\");
    var lineEnd = (lineBroken ? line.length - 1 : line.length);

    if(cmdStart && command != "") {
      command += " && ";
    }
    
    if(cmdStart || includeNextLine) {
      command += line.substring(lineBegin, lineEnd);
    }
    
    includeNextLine = lineBroken;
  }

  return command;
}

function extractIrbCommands(irbBlock) {
  var blockLines = irbBlock.innerText.split("\n");
  var command = "";

  for(var j = 0; j < blockLines.length; j++) {
    var line = blockLines[j];
    
    if(line.startsWith("irb")) {
      if(command != "") {
        command += "; ";
      }
      command += line.split(" # ")[0].substring(11, line.length);
    }
  }

  return command;
}

function createClipboardButton(block, clipboardText) {
  var btn = document.createElement("button")
  btn.setAttribute("class", "hover-button");
  btn.setAttribute("data-clipboard-text", clipboardText);
  block.parentNode.insertBefore(btn, block);

  new Clipboard(btn);
}

var codeBlocks = document.getElementsByTagName("code");

for(var i = 0; i < codeBlocks.length; i++) {
  var block = codeBlocks[i];
  var codeType = block.getAttribute("data-lang");

  if(codeType == "shell") {
    var text = extractShellCommand(block);
  } else if(codeType == "ruby") {
    if(block.innerText.startsWith("irb")) {
      var text = extractIrbCommands(block);
    } else {
      var text = block.innerText;
    }
  } else {
    var text = block.innerText;
  }

  createClipboardButton(block, text);
}
