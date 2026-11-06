# Netlify Functions Worker per VirusTotal

- **Provider**: Netlify (Functions v2)
- **Infrastruttura IP di Uscita**: AWS US-East / Google Cloud
- **Piano Gratuito**: 125.000 richieste al mese
- **Tempo di Deploy**: ~1 minuto

---

### Come Fare il Deploy (Metodo Netlify CLI)

1. Nel tuo terminale locale o nel codespace:
   ```bash
   cd multicloud-workers/netlify
   npx netlify-cli deploy --prod
   ```
2. Netlify ti restituirà l'URL del sito, ad esempio:
   ```text
   https://vt-worker-xyz.netlify.app
   ```
3. Aggiungi questo URL nella scheda **"Cloudflare Workers"** della dashboard.

---

### Come Fare il Deploy (Metodo GitHub Web)

1. Crea un repository GitHub con i file di questa cartella (`netlify.toml` e la cartella `netlify/functions/vt.mjs`).
2. Vai su [https://app.netlify.com/start](https://app.netlify.com/start) e collega il repository.
3. Clicca su **"Deploy Site"**.

---

### Test Rapido
```bash
curl "https://tuo-sito.netlify.app/?hash=44d88612fea8a8f36de82e1278abb02f"
```
