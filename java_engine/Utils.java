// Helper utilities for JSON read/write
import org.json.simple.*;
import org.json.simple.parser.*;
import java.io.*;

public class Utils {

    // Read JSON file and return JSONObject
    public static JSONObject readJSON(String path) throws Exception {
        JSONParser parser = new JSONParser();
        FileReader reader = new FileReader(path);
        Object obj = parser.parse(reader);
        reader.close();
        return (JSONObject) obj;
    }

    // Write JSONObject to file
    public static void writeJSON(String path, JSONObject data) throws IOException {
        FileWriter file = new FileWriter(path);
        file.write(data.toJSONString());
        file.flush();
        file.close();
    }
}
