import json
import xml.etree.ElementTree as ET
from datetime import datetime
from cpe_mapper import CPEMapper


class OutputHandler:
    @staticmethod
    def save_as_json(results, target_ip, output_file):
        """
        스캔 결과를 JSON 형식으로 저장
        """
        # 현재 시간 (Unix Timestamp)
        start_time = int(datetime.now().timestamp())

        # JSON 구조 생성
        ports = [
            {
                "protocol": "tcp",
                "portid": str(result["port"]),
                "state": {
                    "state": result["state"],
                    "reason": "syn-ack"
                },
                "service": {
                    "name": result["service"],
                    "banner": result["banner"],
                    "cpe": result["cpe"]
                }
            }
            for result in results if result["state"].lower() == "open"
        ]

        goormrun = {  # 최상위 키 변경
            "goormrun": {
                "scanner": "goorm",
                "start": start_time,
                "host": [
                    {
                        "address": [
                            {
                                "addr": target_ip,
                                "addrtype": "ipv4"
                            }
                        ],
                        "ports": {
                            "port": ports
                        }
                    }
                ]
            }
        }

        # JSON 파일로 저장
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(goormrun, f, indent=4)
        print(f"[INFO] JSON 저장 완료: {output_file}")

    @staticmethod
    def process_results_with_cpe(results, target_ip, output_file):
        """
        스캔 결과에 CPE 정보를 추가하고 JSON 파일로 저장
        """
        enriched_results = []
        for result in results:
            if result[1].lower() == "open":
                cpe_data = {
                    "vendor": "*",
                    "product": result[2] or "*",
                    "version": result[3] or "*",
                    "extrainfo": "*"
                }
                cpe = CPEMapper.generate_cpe(cpe_data, short_format=False)
                enriched_results.append({
                    "port": result[0],
                    "state": result[1],
                    "service": result[2],
                    "banner": result[3],
                    "cpe": cpe
                })
            else:
                enriched_results.append({
                    "port": result[0],
                    "state": result[1],
                    "service": result[2],
                    "banner": result[3],
                    "cpe": None
                })

        # 결과를 JSON으로 저장
        OutputHandler.save_as_json(
            enriched_results,
            target_ip=target_ip,
            output_file=output_file
        )
    

    @staticmethod
    def save_as_xml(results, output_file):
        """
        스캔 결과를 XML 파일로 저장
        """
        root = ET.Element("goormrun")
        host_element = ET.SubElement(root, "host", attrib={"addr": results["host"]})

        ports_element = ET.SubElement(host_element, "ports")
        for port in results["ports"]:
            if port["state"] in {"closed", "filtered"}:  # 닫힌/필터링된 포트는 저장하지 않음
                continue
            port_element = ET.SubElement(ports_element, "port", attrib={"protocol": "tcp", "portid": str(port["portid"])})
            ET.SubElement(port_element, "state", attrib={"state": port["state"]})
            service_element = ET.SubElement(port_element, "service")
            service_element.set("name", port.get("name", "unknown"))
            if "product" in port:
                service_element.set("product", port["product"])
            if "version" in port:
                service_element.set("version", port["version"])
            if "extrainfo" in port:
                service_element.set("extrainfo", port["extrainfo"])
            if "cpe" in port:
                for cpe_entry in port["cpe"]:
                    ET.SubElement(service_element, "cpe").text = cpe_entry

        tree = ET.ElementTree(root)
        tree.write(output_file, encoding="utf-8", xml_declaration=True)
        print(f"[INFO] Results saved as XML to {output_file}")
