import client from "prom-client"

const register = new client.Registry()

const signatureMatches = new client.Counter({
    name: "blue_agent_signature_matches_total",
    help: "Total number of signature-based detections"
})

const anomalyDetections = new client.Counter({
    name: "blue_agent_anomaly_detections_total",
    help: "Total number of anomaly-based descriptions"
})

const responseDuration = new client.Histogram({
    name:"blue_agent_response_duration_ms",
    help:"Time in ms to process a detection and trigger a remediation",
    buckets: [50, 100, 200, 500, 1000, 2000]
})

register.registerMetric(signatureMatches)
register.registerMetric(anomalyDetections)
register.registerMetric(responseDuration)

client.collectDefaultMetrics({ register })

export { register, signatureMatches, anomalyDetections, responseDuration}