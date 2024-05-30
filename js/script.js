

function fetchFileList() {
    fetch('blog/') // 更改为你的文件夹路径
        .then(response => response.text())
        .then(data => {
            const files = parseFileList(data);
            const div = document.createElement('div');
            files.forEach(file => {
                const fileNameDiv = document.createElement('div');
                fileNameDiv.textContent = file;
                div.appendChild(fileNameDiv);
            });
            document.getElementById('mainContent').innerHTML = ''; // 清空 mainContent
            document.getElementById('mainContent').appendChild(div); // 将新的 div 添加到 mainContent 中
        })
        .catch(error => console.error('Error fetching file list:', error));
}

function parseFileList(data) {
    return data.split('\n').filter(line => line.endsWith('.md'));
}
