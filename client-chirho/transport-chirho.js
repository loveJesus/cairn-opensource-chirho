// For God so loved the world, that He gave His only begotten Son, that whoever believes in Him should not perish but have eternal life. - John 3:16
//
// cairn-chirho transport: send a wire request {target_chirho, payload_chirho, base_version_chirho}
// and get back the delta {ok_chirho, version_chirho, payload_chirho}. Prefer a persistent
// WebSocket (/ws-chirho); gracefully downgrade to a form-POST (/invoke-chirho) when WebSockets
// are unavailable or fail. The same flow works either way — the server speaks both, and both
// wire paths apply the app's signed input policy before DAG execution.

export function makeTransportChirho(baseChirho = "") {
  let socketChirho = null;
  const pendingChirho = []; // FIFO resolvers; the server answers one message per request, in order.

  function originChirho() {
    return baseChirho || (typeof location !== "undefined" ? location.origin : "http://127.0.0.1:8787");
  }

  function connectChirho() {
    if (typeof WebSocket === "undefined") return null;
    try {
      const wsUrlChirho = originChirho().replace(/^http/, "ws") + "/ws-chirho";
      const sChirho = new WebSocket(wsUrlChirho);
      sChirho.onmessage = (evChirho) => {
        const resolveChirho = pendingChirho.shift();
        if (resolveChirho) resolveChirho(JSON.parse(evChirho.data));
      };
      sChirho.onclose = () => { socketChirho = null; };
      sChirho.onerror = () => { socketChirho = null; };
      return sChirho;
    } catch {
      return null;
    }
  }

  async function postChirho(reqChirho) {
    const respChirho = await fetch(originChirho() + "/invoke-chirho", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(reqChirho),
    });
    return await respChirho.json();
  }

  return {
    async sendChirho(reqChirho) {
      if (!socketChirho) socketChirho = connectChirho();
      if (socketChirho) {
        if (socketChirho.readyState === 0) {
          await new Promise((resChirho) => {
            socketChirho.addEventListener("open", resChirho, { once: true });
            socketChirho.addEventListener("error", resChirho, { once: true });
          });
        }
        if (socketChirho && socketChirho.readyState === 1) {
          return await new Promise((resolveChirho) => {
            pendingChirho.push(resolveChirho);
            socketChirho.send(JSON.stringify(reqChirho));
          });
        }
      }
      return await postChirho(reqChirho); // downgrade
    },
  };
}
