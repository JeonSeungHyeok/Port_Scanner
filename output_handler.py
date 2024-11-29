import json
import xml.etree.ElementTree as ET

class OutputHandler:
    @staticmethod
    def save_as_json(results, output_file="output.json"):
        """
        스캔 결과를 JSON 파일로 저장
        """
        formatted_results = [
            {
                "Port": result[0],
                "State": result[1],
                "Service": result[2] if len(result) > 2 else None,
                "Banner": result[3] if len(result) > 3 else None,
            }
            for result in results
        ]
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(formatted_results, f, indent=4)
        print(f"[INFO] Results saved as JSON to {output_file}")

    @staticmethod
    def save_as_xml(results, output_file="output.xml"):
        """
        스캔 결과를 XML 파일로 저장
        """
        root = ET.Element("ScanResults")
        for result in results:
            port_element = ET.SubElement(root, "Port")
            ET.SubElement(port_element, "PortNumber").text = str(result[0])
            ET.SubElement(port_element, "State").text = result[1]
            if len(result) > 2:
                ET.SubElement(port_element, "Service").text = result[2] or "N/A"
            if len(result) > 3:
                ET.SubElement(port_element, "Banner").text = result[3] or "N/A"

        tree = ET.ElementTree(root)
        tree.write(output_file, encoding="utf-8", xml_declaration=True)
        print(f"[INFO] Results saved as XML to {output_file}")
