import winston from "winston";
import { ElasticsearchTransport } from "winston-elasticsearch"
import dotenv from "dotenv"

dotenv.config();

const esTransportOpts = {
    level: "info",
    clientOpts: { node: process.env.ELASTICSEARCH_URL },
    indexPrefix: "blue-agent-logs"
}

const logger = winston.createLogger({
    transports: [ new ElasticsearchTransport(esTransportOpts) ],
    format: winston.format.json(),
})

export default logger;