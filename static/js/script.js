function startProgress() {
  let bar = document.getElementById("progress-bar");
  let width = 0;
  let interval = setInterval(() => {
    if (width >= 100) {
      clearInterval(interval);
    } else {
      width += 2;
      bar.style.width = width + "%";
    }
  }, 100);
}
