const urlInput = document.getElementById("urlInput");
const resultDiv = document.getElementById("result");

const history = [];

function updateHistory() {
  const historyHTML = history
    .map(
      (item) =>
        `<div style="margin-top: 0.5rem; border-top: 1px solid #ddd; padding-top: 0.5rem;">
          <strong>${item.url}</strong><br/>
          <span style="color: ${item.safe ? 'green' : 'red'}">${item.message}</span>
        </div>`
    )
    .join("");
  resultDiv.innerHTML = historyHTML;
}

function checkURL() {
  const url = urlInput.value.trim();
  if (!url) return;

  fetch("http://127.0.0.1:5000/check", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ url }),
  })
    .then((response) => response.json())
    .then((data) => {
      history.unshift({
        url,
        message: data.message,
        safe: data.safe,
      });

      updateHistory();
      urlInput.value = "";
    })
    .catch((error) => {
      console.error("Error:", error);
      resultDiv.innerHTML =
        "<span style='color:red;'>Error contacting the server.</span>";
    });
}
