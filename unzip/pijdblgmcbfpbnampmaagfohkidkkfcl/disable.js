let disabled = true;

// setInterval(() => {
//   document.body.style.background = disabled ? 'lightcoral' : 'lightblue';
// }, 1000);

chrome.runtime.onMessage.addListener((message) => {
  disabled = !!message.disabled;
});

document.addEventListener('keydown', (event) => {
  const isF7 = event.code === 'F7';
  if (isF7 && disabled) event.preventDefault();
});

chrome.runtime.sendMessage('DisableJSInit', () => {});
