const copyrightYear = document.querySelector("#copyright-year");
const passwordFields = document.querySelectorAll("input[type='password']");
const toggleButtons = document.querySelectorAll(".password-toggle-icon i");
const confirmPasswordField = document.querySelector(".confirm-password-input");
const togglePassword = document.querySelector(".password-toggle-icon i");
const confirmTogglePassword = document.querySelector(
  ".confirm-password-toggle-icon i",
);
const toastContainer = document.querySelector(".toast-container");
const toastCloseButton = document.querySelector(".toast-btn");

copyrightYear.textContent = (function () {
  return new Date().getFullYear();
})();

if (toastContainer && toastCloseButton) {
  toastCloseButton.addEventListener("click", () => {
    toastContainer.remove();
  });
  setTimeout(() => {
    toastContainer.remove();
  }, 5000);
}

toggleButtons.forEach((toggle, index) => {
  if (toggle) {
    toggle.addEventListener("click", function () {
      const passwordField = passwordFields[index];
      if (passwordField.type === "password") {
        passwordField.type = "text";
        toggle.classList.remove("fa-eye");
        toggle.classList.add("fa-eye-slash");
      } else {
        passwordField.type = "password";
        toggle.classList.remove("fa-eye-slash");
        toggle.classList.add("fa-eye");
      }
    });
  }
});

document.addEventListener("DOMContentLoaded", function () {
  //capture a user's timezone to a cookie
  let userTimezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
  document.cookie = "user_timezone=" + userTimezone + "; path=/";
});
