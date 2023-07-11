import pytest
from sigma.collection import SigmaCollection
from sigma.backends.carbonblack import CarbonBlackBackend
from sigma.pipelines.carbonblack import CarbonBlackResponse_pipeline, CarbonBlack_pipeline

@pytest.fixture
def cbr_backend():
    return CarbonBlackBackend(CarbonBlackResponse_pipeline())

@pytest.fixture
def cb_backend():
    return CarbonBlackBackend(CarbonBlack_pipeline())

def test_cbr_windows_os_filter(cbr_backend : CarbonBlackBackend):
    assert cbr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    Image: valueA
                condition: sel
        """)
    ) == ['os_type:windows process_name:valueA']

def test_cbr_linux_os_filter(cbr_backend : CarbonBlackBackend):
    assert cbr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: linux
            detection:
                sel:
                    Image: valueA
                condition: sel
        """)
    ) == ['os_type:linux process_name:valueA']

def test_cbr_osx_os_filter(cbr_backend : CarbonBlackBackend):
    assert cbr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: macos
            detection:
                sel:
                    Image: valueA
                condition: sel
        """)
    ) == ['os_type:osx process_name:valueA']

def test_cbr_field_mapping(cbr_backend : CarbonBlackBackend):
    assert cbr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    ProcessId: 12
                    Image: valueA
                    ImagePath: bar bar
                    Description: foo bar
                    Product: bar foo
                    Company: foo foo
                    CommandLine: invoke-mimikatz
                    CurrentDirectory: etc
                    User: administrator
                    md5: asdfasdfasdfasdfasdf
                    sha256: asdfasdfasdfasdfasdfasdfasdfasdf
                    ParentProcessId: 13
                    ParentImage: valueB
                    TargetFilename: test.txt
                    ImageLoaded: test.dll
                    TargetObject: HKCU
                    DestinationHostname: google.com
                    DestinationPort: 445
                    DestinationIp: 1.1.1.1
                    SourceIp: 2.2.2.2
                    SourcePort: 135
                    dst_ip: 3.3.3.3
                    src_ip: 4.4.4.4
                    dst_port: 80
                    src_port: 443
                condition: sel
        """)
    ) == ['process_pid:12 process_name:valueA path:bar\\ bar file_desc:foo\\ bar product_name:bar\\ foo ' + 
          'company_name:foo\\ foo cmdline:invoke-mimikatz process_name:etc username:administrator ' + 
          'md5:asdfasdfasdfasdfasdf sha256:asdfasdfasdfasdfasdfasdfasdfasdf parent_pid:13 parent_name:valueB ' + 
          'filemod:test.txt modload:test.dll regmod:HKCU domain:google.com ipport:445 ipaddr:1.1.1.1 ' + 
          'ipaddr:2.2.2.2 ipport:135 ipaddr:3.3.3.3 ipaddr:4.4.4.4 ipport:80 ipport:443']

def test_cbr_unsupported_rule_type(cbr_backend : CarbonBlackBackend):
  with pytest.raises(ValueError):
    cbr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    Image: valueA
                    CommandLine: invoke-mimikatz
                    ParentImage: valueB
                    ParentCommandLine: Get-Path
                condition: sel
        """)
    )

def test_cbr_unsupported_field_name(cbr_backend : CarbonBlackBackend):
  with pytest.raises(ValueError):
    cbr_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    FOO: bar
                condition: sel
        """)
    )

def test_cb_windows_os_filter(cb_backend : CarbonBlackBackend):
    assert cb_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    Image: valueA
                condition: sel
        """)
    ) == ['device_os:WINDOWS process_name:valueA']

def test_cb_linux_os_filter(cb_backend : CarbonBlackBackend):
    assert cb_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: linux
            detection:
                sel:
                    Image: valueA
                condition: sel
        """)
    ) == ['device_os:LINUX process_name:valueA']

def test_cb_osx_os_filter(cb_backend : CarbonBlackBackend):
    assert cb_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: macos
            detection:
                sel:
                    Image: valueA
                condition: sel
        """)
    ) == ['device_os:MAC process_name:valueA']

def test_cb_field_mapping(cb_backend : CarbonBlackBackend):
    assert cb_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    ProcessId: 12
                    Image: valueA
                    Description: foo bar
                    Product: bar foo
                    Company: foo foo
                    CommandLine: invoke-mimikatz
                    CurrentDirectory: etc
                    User: administrator
                    IntegrityLevel: bar bar
                    ParentProcessId: 13
                    ParentImage: valueB
                    ParentCommandLine: invoke-atomic
                    OriginalFileName: cobalt.exe
                    TargetFilename: test.txt
                    ImageLoaded: test.dll
                    Signature: Microsoft
                    TargetObject: HKCU
                    DestinationHostname: google.com
                    DestinationPort: 445
                    DestinationIp: 1.1.1.1
                    SourceIp: 2.2.2.2
                    SourcePort: 135
                    Protocol: UDP
                    dst_ip: 3.3.3.3
                    src_ip: 4.4.4.4
                    dst_port: 80
                    src_port: 443
                    DstPort: 8080
                    SrcPort: 5900
                condition: sel
        """)
    ) == ['process_pid:12 process_name:valueA process_file_description:foo\\ bar process_product_name:bar\\ foo ' + 
          'process_company_name:foo\\ foo process_cmdline:invoke-mimikatz process_name:etc ' + 
          'process_username:administrator process_integrity_level:bar\\ bar parent_pid:13 parent_name:valueB ' + 
          'parent_cmdline:invoke-atomic process_original_filename:cobalt.exe filemod_name:test.txt ' + 
          'modload_name:test.dll modload_publisher:Microsoft regmod_name:HKCU netconn_domain:google.com ' + 
          'netconn_port:445 (netconn_ipv4:1.1.1.1 OR netconn_ipv6:1.1.1.1) (netconn_ipv4:2.2.2.2 OR netconn_ipv6:2.2.2.2) ' + 
          'netconn_port:135 (netconn_protocol:UDP OR netconn_application_protocol:UDP) (netconn_ipv4:3.3.3.3 OR netconn_ipv6:3.3.3.3) ' + 
          '(netconn_ipv4:4.4.4.4 OR netconn_ipv6:4.4.4.4) netconn_port:80 netconn_port:443 netconn_port:8080 netconn_port:5900']

def test_cb_process_field_mapping(cb_backend : CarbonBlackBackend):
    assert cb_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    md5: asdfasdfasdfasdf
                    sha256: qwerqwerqwerqwer
                condition: sel
        """)
    ) == ['process_hash:asdfasdfasdfasdf process_hash:qwerqwerqwerqwer']

def test_cb_image_load_field_mapping(cb_backend : CarbonBlackBackend):
    assert cb_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: image_load
                product: test_product
            detection:
                sel:
                    md5: asdfasdfasdfasdf
                    sha256: qwerqwerqwerqwer
                condition: sel
        """)
    ) == ['modload_hash:asdfasdfasdfasdf modload_hash:qwerqwerqwerqwer']


def test_cb_filemod_field_mapping(cb_backend : CarbonBlackBackend):
    assert cb_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: file_event
                product: test_product
            detection:
                sel:
                    md5: asdfasdfasdfasdf
                    sha256: qwerqwerqwerqwer
                condition: sel
        """)
    ) == ['filemod_hash:asdfasdfasdfasdf filemod_hash:qwerqwerqwerqwer']

def test_cb_unsupported_rule_type(cb_backend : CarbonBlackBackend):
  with pytest.raises(ValueError):
    cb_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    Image: valueA
                    CommandLine: invoke-mimikatz
                    ParentImage: valueB
                    ParentCommandLine: Get-Path
                condition: sel
        """)
    )

def test_cb_unsupported_field_name(cb_backend : CarbonBlackBackend):
  with pytest.raises(ValueError):
    cb_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: test_product
            detection:
                sel:
                    FOO: bar
                condition: sel
        """)
    )
