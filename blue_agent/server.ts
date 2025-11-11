import express from "express";
import { createClient } from "redis";
import dotenv from "dotenv";
import { register, signatureMatches, anomalyDetections, responseDuration} from "./metrics"
import logger from "./logger"

dotenv.config();

async function startServer() {
    const redisClient = createClient({
        url: process.env.REDIS_URL,
    })

    redisClient.on("error", (err) => console.error("Redis Client Error :", err))
    await redisClient.connect()

    const app = express()

    app.use(express.json())

    app.post("/quarantine", async (req, res) => {
        const { ip, duration, reason } = req.body

        if (!ip || typeof duration !== "number") {
            return res.status(400).json({
                error: "Both 'ip' (string) and 'duration' (number of seconds) are required"
            })
        }

        try {
            const value = reason || "quarantined"
            await redisClient.set(`block:${ip}`, value, {
                EX: duration
            })
            return res.status(200).json({
                success: true,
                message: `IP ${ip} quarantined for ${duration} seconds`,
            })
        } catch (err) {
            console.error("Error setting quarantine in Redis :", err)
            return res.status(500).json({
                success: false,
                error: "Internal server error"
            })
        }
    });

    app.post("/detect", async(req, res)=>{
        const start = Date.now()
        const {ip, promptSnippet, anomalyScore, type} = req.body

        logger.info({
            event: "detection",
            type,
            ip,
            promptSnippet,
            anomalyScore,
            timestamp: new Date().toISOString()
        })        

        if(type === "signature"){
            signatureMatches.inc();
        } else if( type === "anomaly"){
            anomalyDetections.inc();
        }

        // Perform remediation logic

        responseDuration.observe(Date.now() - start)
        return res.status(200).json({
            success: true
        })
    });

    app.get("/metrics", async(_req, res)=>{
        res.setHeader("Content-Type", register.contentType);
        res.send(await register.metrics())
    })

    app.post("/remediate", async (req, res) => {
        const { ip } = req.body

        if (!ip) {
            return res
                .status(400)
                .json({
                    error: "ip (string) is required for remediation"
                })
        }

        try {
            const deleted = await redisClient.del(`block:${ip}`)
            if (deleted === 1) {
                return res.status(200).json({
                    success: true,
                    message: `IP ${ip} removed from quarantine`
                })
            } else {
                return res.status(404).json({
                    success: false,
                    message: `IP ${ip} was not found in quarantine`
                })
            }
        } catch (err) {
            console.error("Error deleting quarantine key in Redis: ", err)
            return res.status(500).json({
                success: false,
                error: "Internal Server Error",
            })
        }
    });

    app.get("/status/:ip", async (req, res) => {
        const { ip } = req.params
        try {
            const ttl = await redisClient.ttl(`block:${ip}`)
            if (ttl > 0) {
                const reason = await redisClient.get(`block:${ip}`)
                return res.status(200).json({
                    quarantined: true,
                    ttlSeconds: ttl,
                    reason: reason || "unknown"
                })
            } else {
                return res.status(200).json({ quarantined: false })
            }
        } catch (err) {
            console.error("Error checking quarantine status in Redis: ", err)
            return res.status(500).json({
                success: false,
                error: "Internal server error"
            })
        }
    });

    // Assuming a TypeScript file (e.g., src/server.ts)
    // Setup Express + Redis exactly as you have already.

    app.post("/flag", async (req, res) => {
        const { ip, anomalyScore, reason } = req.body;
        if (!ip || typeof anomalyScore !== "number") {
            return res.status(400).json({ error: "ip (string) and anomalyScore (number) required" });
        }

        // Log the borderline alert for manual review; e.g., store in Redis (or a database) 
        // prefer maybe a list of flagged IPs for later review
        const key = `flag:${ip}`;
        const value = JSON.stringify({ anomalyScore, reason, flaggedAt: Date.now() });
        // Set maybe with no expiry or some review TTL
        await redisClient.set(key, value, { EX: 60 * 60 * 24 });  // e.g., 24 h TTL

        return res.status(200).json({
            success: true,
            message: `IP ${ip} flagged for manual review (score ${anomalyScore})`
        });
    });

    const PORT = process.env.PORT
    app.listen(PORT, () => console.log(`Blue agent response service listening on port ${PORT}`))
}

startServer().catch((err) => {
    console.error("Failed to start server: ", err)
    process.exit(1)
});