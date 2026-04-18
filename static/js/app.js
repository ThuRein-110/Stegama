const fileInput = document.getElementById('fileInput');
const dropTitle = document.querySelector('.drop-title');

if (fileInput && dropTitle) {
  fileInput.addEventListener('change', () => {
    if (fileInput.files.length > 0) {
      dropTitle.textContent = `Selected: ${fileInput.files[0].name}`;
    }
  });
}
