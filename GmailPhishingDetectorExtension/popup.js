document.getElementById('openTool').addEventListener('click', function() {
  chrome.tabs.create({ url: "http://localhost:8000/index.html" });
});
