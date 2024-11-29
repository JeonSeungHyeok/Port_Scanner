class CPEMapper:
    @staticmethod
    def generate_cpe(service_info, short_format=False):
        """
        CPE 문자열 생성
        """
        part = "a"  # 애플리케이션 기준
        vendor = service_info.get("vendor", "*").lower().strip()  # 기본값을 *로 설정
        product = service_info.get("product", "*").lower().strip()  # 기본값을 *로 설정
        version = service_info.get("version", "*").strip()  # 기본값을 *로 설정
        extrainfo = str(service_info.get("extrainfo", "*")).strip()  # None 방지를 위해 str() 사용

        if short_format:
            return f"cpe:2.3:{part}:{vendor}:{product}:{version}:{extrainfo}"
        else:
            return f"cpe:2.3:{part}:{vendor}:{product}:{version}:{extrainfo}:*:*:*:*:*:*"

    @staticmethod
    def map_results_to_cpe(results, short_format=False):
        """
        결과 리스트에서 CPE 매핑 (닫힌 포트와 필터링된 포트는 제외)
        """
        cpe_list = []
        for result in results:
            # 튜플에서 데이터 추출
            port, state, service, version = result[:4]
            extrainfo = result[4] if len(result) > 4 else "*"

            # 닫힌 포트와 필터링된 포트 제외
            invalid_states = {"closed", "filtered"}
            if state.lower() in invalid_states:
                continue

            # 서비스 정보 구성
            service_info = {
                #"vendor": "unknown",  # Vendor는 튜플 데이터에서 직접 추출할 수 없으므로 기본값 사용
                "product": service,
                "version": version,
                "extrainfo": extrainfo,
            }
            cpe = CPEMapper.generate_cpe(service_info, short_format=short_format)
            cpe_list.append(cpe)
        return cpe_list

