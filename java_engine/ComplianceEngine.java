// Java Compliance Engine main class
import org.json.simple.*;
import org.json.simple.parser.*;
import java.io.*;

public class ComplianceEngine {

    public static void main(String[] args) {
        try {
            // Load AWS configuration JSON
            JSONObject awsData = Utils.readJSON("../backend/data/aws_config.json");

            // Extract sections
            JSONObject s3 = (JSONObject) awsData.get("S3");
            JSONObject iam = (JSONObject) awsData.get("IAM");
            JSONObject ec2 = (JSONObject) awsData.get("EC2");

            // Evaluate compliance using Rules class
            Rules rules = new Rules();
            JSONObject report = rules.evaluateCompliance(s3, iam, ec2);

            // Write report.json output
            Utils.writeJSON("../backend/data/report.json", report);

            System.out.println("✅ Compliance report generated successfully!");
        } 
        catch (FileNotFoundException e) {
            System.out.println("❌ Error: aws_config.json not found. Make sure it exists in backend/data/");
        } 
        catch (Exception e) {
            e.printStackTrace();
        }
    }
}
