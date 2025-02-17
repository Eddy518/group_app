/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./myapp/templates/**/*.html",
    "./myapp/static/src/**/*.js",
    "./node_modules/flowbite/**/*.js",
  ],
  theme: {
    extend: {},
  },
  plugins: [require("flowbite/plugin")],
};
