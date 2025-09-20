import 'dotenv/config';
import express from 'express';

const app = express();
app.use(express.json());

const PORT = Number(process.env.PORT || 9000);

app.get('/healthz', (_req, res) => res.send('ok'));

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`gateway-agent listening on :${PORT}`);
});