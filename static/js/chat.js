const chatBox = document.getElementById("chat-box");
const userInput = document.getElementById("user-input");
const sendBtn = document.getElementById("send-btn");

function addMessage(text, sender) {
    const div = document.createElement("div");
    div.classList.add("message", sender === "user" ? "user-message" : "bot-message");

    // Allow basic formatting
    text = text.replace(/\n/g, '<br>');
    div.innerHTML = text;

    chatBox.appendChild(div);
    chatBox.scrollTop = chatBox.scrollHeight;
}

async function sendMessage() {
    const text = userInput.value.trim();
    if (!text) return;

    addMessage(text, "user");
    userInput.value = "";

    // Add loading indicator
    const loadingDiv = document.createElement("div");
    loadingDiv.classList.add("message", "bot-message");
    loadingDiv.textContent = "...";
    chatBox.appendChild(loadingDiv);
    chatBox.scrollTop = chatBox.scrollHeight;

    try {
        const response = await fetch("/api/chat", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: text })
        });

        const data = await response.json();

        // Remove loading indicator
        chatBox.removeChild(loadingDiv);

        addMessage(data.answer, "bot");

        // Render Options
        if (data.options && data.options.length > 0) {
            const optionsDiv = document.createElement("div");
            optionsDiv.classList.add("message", "bot-message");
            optionsDiv.style.background = "transparent";
            optionsDiv.style.padding = "0";

            data.options.forEach(opt => {
                const btn = document.createElement("button");
                btn.textContent = opt;
                btn.style.margin = "6px 6px 0 0";
                btn.style.padding = "6px 14px";
                btn.style.cursor = "pointer";
                btn.style.borderRadius = "20px"; // More rounded
                btn.style.border = "1px solid #ff5722";
                btn.style.background = "white";
                btn.style.color = "#ff5722";
                btn.style.fontSize = "0.9rem";
                btn.style.fontWeight = "500";
                btn.style.transition = "all 0.2s";

                btn.onmouseover = () => { btn.style.background = "#ff5722"; btn.style.color = "white"; btn.style.transform = "translateY(-1px)"; };
                btn.onmouseout = () => { btn.style.background = "white"; btn.style.color = "#ff5722"; btn.style.transform = "translateY(0)"; };

                btn.onclick = () => {
                    const redirects = {
                        "View Cart": "/cart",
                        "Checkout": "/cart",
                        "Book a Table": "/reserve",
                        "My Orders": "/orders",
                        "View My Reservations": "/reservations"
                    };

                    if (redirects[opt]) {
                        window.location.href = redirects[opt];
                        return;
                    }

                    userInput.value = opt;
                    sendMessage();
                };
                optionsDiv.appendChild(btn);
            });
            chatBox.appendChild(optionsDiv);
            chatBox.scrollTop = chatBox.scrollHeight;
        }

    } catch (error) {
        chatBox.removeChild(loadingDiv);
        addMessage("Sorry, I encountered an error.", "bot");
        console.error(error);
    }
}

sendBtn.addEventListener("click", sendMessage);
userInput.addEventListener("keypress", e => {
    if (e.key === "Enter") sendMessage();
});
