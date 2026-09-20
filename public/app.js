"use strict";

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-copy]").forEach((button) => {
    button.addEventListener("click", async () => {
      const value = button.dataset.copy;

      try {
        await navigator.clipboard.writeText(value);

        const original = button.textContent;

        button.textContent = "Copied";

        setTimeout(() => {
          button.textContent = original;
        }, 1200);
      } catch {
        button.textContent = "Copy failed";
      }
    });
  });
});
