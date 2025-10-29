// Helper class for compliance rules
import org.json.simple.*;
import java.util.*;

public class Rules {

    public JSONObject evaluateCompliance(JSONObject s3, JSONObject iam, JSONObject ec2) {
        JSONArray violations = new JSONArray();
        int high = 0, medium = 0, low = 0;

        // --- 🪣 S3 Checks ---
        JSONArray buckets = (JSONArray) s3.get("Buckets");
        for (Object b : buckets) {
            JSONObject bucket = (JSONObject) b;

            boolean isPublic = (Boolean) bucket.get("ACL_Public");
            boolean encrypted = (Boolean) bucket.get("Encryption");

            if (isPublic) {
                violations.add("S3 bucket '" + bucket.get("Name") + "' is public");
                high++;
            }
            if (!encrypted) {
                violations.add("S3 bucket '" + bucket.get("Name") + "' is not encrypted");
                medium++;
            }
        }

        // --- 👥 IAM Checks ---
        JSONObject userMFA = (JSONObject) iam.get("UserMFA");
        for (Object key : userMFA.keySet()) {
            boolean mfa = (Boolean) userMFA.get(key);
            if (!mfa) {
                violations.add("IAM user '" + key + "' does not have MFA enabled");
                high++;
            }
        }

        // --- 💻 EC2 Checks ---
        JSONArray instances = (JSONArray) ec2.get("Instances");
        for (Object i : instances) {
            JSONObject instance = (JSONObject) i;
            JSONArray sg = (JSONArray) instance.get("SecurityGroups");

            if (sg.isEmpty()) {
                violations.add("EC2 instance '" + instance.get("InstanceId") + "' has no Security Groups");
                low++;
            }
        }

        // --- 🧮 Calculate Compliance Score ---
        int totalRules = 4;
        int failed = high + medium + low;
        int passed = Math.max(0, totalRules - failed);
        int complianceScore = (passed * 100) / totalRules;

        // --- 📄 Build Report JSON ---
        JSONObject report = new JSONObject();
        report.put("Compliance_Score", complianceScore);
        report.put("High_Risks", high);
        report.put("Medium_Risks", medium);
        report.put("Low_Risks", low);
        report.put("Violations", violations);

        return report;
    }
}
