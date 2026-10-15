// VIGILIS — minimal interaction layer.
// Communicates genuine progress on submit rather than decorative animation,
// per the UX Specification's "Progress Communication" principle.

document.addEventListener("DOMContentLoaded", () => {
  const form = document.querySelector(".scan-form");
  if (!form) return;

  form.addEventListener("submit", () => {
    const button = form.querySelector(".scan-button");
    if (!button) return;
    button.disabled = true;
    button.textContent = "Assessing website…";
  });
});
