(async () => {
  const enabledKey = 'enabled';
  const getDisabled = async () => {
    const obj = await chrome.storage.local.get([enabledKey]);
    return !obj[enabledKey];
  };

  /** @type {{[windowId: number]: number[]}} */
  const windowTabIds = {};

  const setIcon = async () => {
    const disabled = await getDisabled();
    if (disabled) {
      chrome.action.setIcon({
        path: {
          128: 'icons/icon128.png'
        }
      });
    } else {
      chrome.action.setIcon({
        path: {
          128: 'icons/icon128-2.png'
        }
      });
    }
  };

  const setDisabled = async () => {
    const disabled = await getDisabled();
    Object.keys(windowTabIds).forEach((windowId) => {
      windowTabIds[windowId].forEach((tabId) => {
        chrome.tabs.sendMessage(tabId, {
          disabled
        });
      });
    });
  };
  await setIcon();

  chrome.action.onClicked.addListener(async () => {
    const disabled = await getDisabled();
    // Set disabled = !disabled
    if (disabled) await chrome.storage.local.set({ [enabledKey]: true });
    else await chrome.storage.local.remove([enabledKey]);

    setIcon();
    setDisabled();
  });

  chrome.tabs.onRemoved.addListener((tabId, removeInfo) => {
    const windowId = removeInfo.windowId;
    console.log(`Window ${windowId} Tab ${tabId} is removed.`);
    if (windowTabIds[windowId]) {
      const index = windowTabIds[windowId].find((id) => id === tabId);
      if (index >= 0) windowTabIds[windowId].splice(index, 1);
    }
    console.log(`windowTabIds = `, windowTabIds);
  });

  chrome.windows.onRemoved.addListener((windowId) => {
    delete windowTabIds[windowId];
    console.log(`windowTabIds = `, windowTabIds);
  });

  // Update disabled after tab init
  chrome.runtime.onMessage.addListener(
    async (message, sender, sendResponse) => {
      if (message === 'DisableJSInit') {
        const windowId = sender.tab.windowId;
        const tabId = sender.tab.id;
        if (windowTabIds[windowId]) windowTabIds[windowId].push(tabId);
        else windowTabIds[windowId] = [tabId];
        console.log(`DisableJSInit window ${windowId} tab ${tabId}`);
        console.log(`windowTabIds = `, windowTabIds);
        chrome.tabs.sendMessage(tabId, {
          disabled: await getDisabled()
        });
      }
    }
  );
})();
