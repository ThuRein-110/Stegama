document.addEventListener('DOMContentLoaded', () => {
  wireUpload();
  wireTabs();
  wireFilters();
  drawHeroCanvas();
});

function wireUpload() {
  const fileInput = document.getElementById('fileInput');
  const dropzone = document.getElementById('dropzone');
  const dropTitle = document.querySelector('.drop-title');
  const uploadForm = document.getElementById('uploadForm');

  if (!fileInput || !dropzone || !dropTitle) {
    return;
  }

  const setFile = (file) => {
    if (!file) {
      return;
    }
    dropTitle.textContent = `Selected: ${file.name}`;
  };

  fileInput.addEventListener('change', () => {
    setFile(fileInput.files[0]);
  });

  ['dragenter', 'dragover'].forEach((eventName) => {
    dropzone.addEventListener(eventName, (event) => {
      event.preventDefault();
      dropzone.classList.add('is-dragging');
    });
  });

  ['dragleave', 'drop'].forEach((eventName) => {
    dropzone.addEventListener(eventName, (event) => {
      event.preventDefault();
      dropzone.classList.remove('is-dragging');
    });
  });

  dropzone.addEventListener('drop', (event) => {
    const file = event.dataTransfer.files[0];
    if (!file) {
      return;
    }
    fileInput.files = event.dataTransfer.files;
    setFile(file);
  });

  if (uploadForm) {
    uploadForm.addEventListener('submit', () => {
      const button = uploadForm.querySelector('button[type="submit"]');
      if (button) {
        button.disabled = true;
        button.textContent = 'Analyzing artifact...';
      }
    });
  }
}

function wireTabs() {
  const buttons = document.querySelectorAll('[data-tab-target]');
  if (!buttons.length) {
    return;
  }

  buttons.forEach((button) => {
    button.addEventListener('click', () => {
      const targetId = button.dataset.tabTarget;
      document.querySelectorAll('.tab-button').forEach((item) => item.classList.remove('is-active'));
      document.querySelectorAll('.tab-panel').forEach((panel) => panel.classList.remove('is-active'));
      button.classList.add('is-active');
      const target = document.getElementById(targetId);
      if (target) {
        target.classList.add('is-active');
      }
    });
  });
}

function wireFilters() {
  const inputs = document.querySelectorAll('[data-filter-input]');
  inputs.forEach((input) => {
    input.addEventListener('input', () => {
      const table = document.getElementById(input.dataset.filterInput);
      if (!table) {
        return;
      }
      const needle = input.value.trim().toLowerCase();
      table.querySelectorAll('tbody tr').forEach((row) => {
        row.hidden = needle && !row.textContent.toLowerCase().includes(needle);
      });
    });
  });
}

function drawHeroCanvas() {
  const canvas = document.getElementById('heroSignalCanvas');
  if (!canvas) {
    return;
  }

  const context = canvas.getContext('2d');
  const points = Array.from({ length: 80 }, (_, index) => ({
    x: Math.random(),
    y: Math.random(),
    phase: index * 0.17,
    speed: 0.0015 + Math.random() * 0.0018,
  }));

  const resize = () => {
    const rect = canvas.getBoundingClientRect();
    const ratio = window.devicePixelRatio || 1;
    canvas.width = Math.max(1, Math.floor(rect.width * ratio));
    canvas.height = Math.max(1, Math.floor(rect.height * ratio));
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
  };

  const render = (time) => {
    const width = canvas.clientWidth;
    const height = canvas.clientHeight;
    context.clearRect(0, 0, width, height);
    context.fillStyle = '#070b10';
    context.fillRect(0, 0, width, height);

    context.strokeStyle = 'rgba(56, 214, 232, 0.08)';
    context.lineWidth = 1;
    for (let x = 0; x < width; x += 42) {
      context.beginPath();
      context.moveTo(x, 0);
      context.lineTo(x, height);
      context.stroke();
    }
    for (let y = 0; y < height; y += 42) {
      context.beginPath();
      context.moveTo(0, y);
      context.lineTo(width, y);
      context.stroke();
    }

    points.forEach((point, index) => {
      const pulse = Math.sin(time * point.speed + point.phase);
      const x = point.x * width;
      const y = ((point.y + time * point.speed * 0.035) % 1) * height;
      const barHeight = 20 + Math.abs(pulse) * 76;
      context.fillStyle = index % 5 === 0 ? 'rgba(245, 184, 75, 0.35)' : 'rgba(56, 214, 232, 0.28)';
      context.fillRect(x, y, 2, barHeight);
      context.fillStyle = index % 7 === 0 ? 'rgba(239, 107, 115, 0.42)' : 'rgba(125, 220, 154, 0.32)';
      context.fillRect(x - 3, y + barHeight + 5, 8, 2);
    });

    requestAnimationFrame(render);
  };

  resize();
  window.addEventListener('resize', resize);
  requestAnimationFrame(render);
}
