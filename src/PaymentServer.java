import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;

public class PaymentServer {

    // In a real app, load this from ENV variables
    private static final String SHARED_SECRET = "super_secure_shared_secret_key";
    private static final long TOKEN_VALIDITY_SECONDS = 60;

    // Mock Database (User ID -> Balance)
    private static final Map<String, Double> userWallets = new ConcurrentHashMap<>();

    // Mock storage for processed tokens (Token -> Status)
    private static final Map<String, String> transactionStatus = new ConcurrentHashMap<>();

    public static void main(String[] args) throws IOException {
        // Seed database
        userWallets.put("user_123", 500.00);
        userWallets.put("user_12345", 500.00);
        userWallets.put("merc_999", 0.00);

        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);

        // Define Endpoints
        server.createContext("/health", exchange -> sendResponse(exchange, 200, "OK"));
        server.createContext("/transaction/process", new TransactionHandler());
        server.createContext("/transaction/status", new StatusHandler());
        server.createContext("/balance", new BalanceHandler());

        server.setExecutor(Executors.newCachedThreadPool()); // Java 19+ feature, or use newCachedThreadPool for 17
        System.out.println("Server started on port 8000...");
        server.start();
    }

    static class StatusHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            // Expecting GET /transaction/status?token=BASE64_TOKEN
            String query = exchange.getRequestURI().getQuery();
            String token = query.split("=")[1];

            String status = transactionStatus.getOrDefault(token, "PENDING");
            sendResponse(exchange, 200, status);
        }
    }

    static class BalanceHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            // Expecting GET /balance?userId=user_123
            String query = exchange.getRequestURI().getQuery();
            if (query == null || !query.contains("=")) {
                sendResponse(exchange, 400, "Missing userId");
                return;
            }

            String userId = query.split("=")[1];
            Double balance = userWallets.getOrDefault(userId, 0.0);

            // Return balance as a plain string (e.g., "500.00")
            sendResponse(exchange, 200, String.format("%.2f", balance));
        }
    }

    // Java 17 Record for structured data
    record PaymentRequest(String scannedToken, String merchantId, double amount) {}

    static class TransactionHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!"POST".equals(exchange.getRequestMethod())) {
                sendResponse(exchange, 405, "Method Not Allowed");
                return;
            }

            // Simple body parsing (Assuming JSON-like format or simple string for this demo)
            // Format expected: "token|merchantId|amount"
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String[] parts = body.split("\\|");

            if (parts.length != 3) {
                sendResponse(exchange, 400, "Invalid Format. Use: token|merchantId|amount");
                return;
            }

            var request = new PaymentRequest(parts[0], parts[1], Double.parseDouble(parts[2]));

            try {
                processPayment(request);
                sendResponse(exchange, 200, "Transaction Successful");
            } catch (IllegalArgumentException e) {
                sendResponse(exchange, 403, "Declined: " + e.getMessage());
            } catch (Exception e) {
                e.printStackTrace();
                sendResponse(exchange, 500, "Internal Error");
            }
        }

        private void processPayment(PaymentRequest req) throws Exception {
            // 1. Parse and Validate Token
            // Token Format: base64(userId:timestamp:signature)
            String decoded = new String(Base64.getDecoder().decode(req.scannedToken), StandardCharsets.UTF_8);
            String[] tokenParts = decoded.split(":"); // [userId, timestamp, signature]

            if (tokenParts.length != 3) throw new IllegalArgumentException("Corrupted Token");

            String userId = tokenParts[0];
            long timestamp = Long.parseLong(tokenParts[1]);
            String receivedSig = tokenParts[2];

            // 2. Check Expiration
            if (Instant.now().getEpochSecond() - timestamp > TOKEN_VALIDITY_SECONDS) {
                throw new IllegalArgumentException("Token Expired");
            }

            // 3. Verify Signature
            String payload = userId + ":" + timestamp;
            String expectedSig = hmacSha256(payload, SHARED_SECRET);

            if (!expectedSig.equals(receivedSig)) {
                throw new IllegalArgumentException("Invalid Signature");
            }

            // 4. Execute Transaction
            synchronized (userWallets) {
                double userBal = userWallets.getOrDefault(userId, 0.0);
                if (userBal < req.amount) throw new IllegalArgumentException("Insufficient Funds");

                userWallets.put(userId, userBal - req.amount);
                userWallets.put(req.merchantId, userWallets.getOrDefault(req.merchantId, 0.0) + req.amount);

                transactionStatus.put(req.scannedToken(), "SUCCESS");
                System.out.printf("Transferred $%.2f from %s to %s%n", req.amount, userId, req.merchantId);
            }
        }
    }

    private static String hmacSha256(String data, String key) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        sha256_HMAC.init(secret_key);
        return bytesToHex(sha256_HMAC.doFinal(data.getBytes(StandardCharsets.UTF_8)));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private static void sendResponse(HttpExchange exchange, int code, String response) throws IOException {
        exchange.sendResponseHeaders(code, response.length());
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(response.getBytes());
        }
    }
}