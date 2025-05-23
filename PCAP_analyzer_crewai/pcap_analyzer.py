import os
import sys
from dotenv import load_dotenv
from crewai import Agent, Task, Crew
from litellm import completion
from scapy.all import rdpcap, IP, TCP, UDP, ICMP
import matplotlib.pyplot as plt
import networkx as nx
from collections import Counter

# Tải biến môi trường từ file .env
load_dotenv()

pcap_file = "pcap_normal.pcap"

# Kiểm tra API key và api_base
api_key = os.getenv("DEEPSEEK_API_KEY")
api_base = os.getenv("DEEPSEEK_API_BASE")
if not api_key:
    print("Lỗi: DEEPSEEK_API_KEY không được tìm thấy. Vui lòng đặt biến môi trường hoặc trong file .env.")
    sys.exit(1)
if not api_base:
    print("Cảnh báo: DEEPSEEK_API_BASE không được tìm thấy. Sử dụng endpoint mặc định của DeepSeek.")
    api_base = "https://api.deepseek.com"

# Hàm gọi DeepSeek API qua LiteLLM
def call_deepseek(prompt):
    try:
        response = completion(
            model="deepseek/deepseek-chat",
            messages=[{"role": "user", "content": prompt}],
            api_key=api_key,
            api_base=api_base,
            temperature=0.7,
            max_tokens=1000
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"Lỗi khi gọi DeepSeek API: {str(e)}")
        sys.exit(1)

# Hàm trích xuất thông tin gói tin
def extract_packet_info(pcap_file):
    try:
        # Nếu file không tồn tại với đường dẫn tương đối, thử chuyển sang đường dẫn tuyệt đối của script
        if not os.path.exists(pcap_file):
            # Thử lấy đường dẫn tính từ thư mục chứa script
            script_dir = os.path.dirname(os.path.abspath(__file__))
            alt_path = os.path.join(script_dir, pcap_file)
            if os.path.exists(alt_path):
                pcap_file = alt_path
            else:
                print(f"Lỗi: Không tìm thấy file '{pcap_file}' ở cả đường dẫn tương đối và tuyệt đối.\n"
                      f"Hãy chắc chắn rằng file .pcap nằm trong thư mục: {script_dir}")
                sys.exit(1)

        # In đường dẫn tuyệt đối để debug
        abs_path = os.path.abspath(pcap_file)
        print(f"Đang đọc file PCAP từ: {abs_path}")

        packets = rdpcap(abs_path)
        packet_data = []

        for pkt in packets:
            if IP in pkt:
                info = {
                    "src_ip": pkt[IP].src,
                    "dst_ip": pkt[IP].dst,
                    "protocol": "Unknown"
                }
                if TCP in pkt:
                    info["protocol"] = "TCP"
                elif UDP in pkt:
                    info["protocol"] = "UDP"
                elif ICMP in pkt:
                    info["protocol"] = "ICMP"
                packet_data.append(info)

        total_packets = len(packet_data)
        print(f"Tổng số packet: {total_packets}")
        if total_packets > 10:
            print("Hiển thị 10 packet đầu tiên:")
            for i, pkt in enumerate(packet_data[:10], 1):
                print(f"Packet {i}: {pkt}")
            print(f"... và {total_packets - 10} packet khác.")
        else:
            print("Danh sách tất cả packet:")
            for i, pkt in enumerate(packet_data, 1):
                print(f"Packet {i}: {pkt}")

        return packet_data
    except Exception as e:
        print(f"Lỗi khi đọc file PCAP: {str(e)}")
        print("Đề xuất: Đảm bảo file là định dạng PCAP hoặc PCAPNG hợp lệ và bạn có quyền truy cập.")
        sys.exit(1)

# Hàm đếm host và liệt kê các kết nối
def analyze_hosts(task_output):
    try:
        # Lấy dữ liệu từ task_output (có thể là TaskOutput object hoặc danh sách trực tiếp)
        if hasattr(task_output, 'raw_output'):
            packet_data = task_output.raw_output
        else:
            packet_data = task_output
        
        if not isinstance(packet_data, list):
            print(f"Lỗi: packet_data không phải là danh sách, kiểu dữ liệu: {type(packet_data)}")
            # Thử trích xuất lại từ file PCAP trực tiếp
            packet_data = extract_packet_info(pcap_file)
            if not isinstance(packet_data, list):
                sys.exit(1)
        
        hosts = set()
        edges = []
        for pkt in packet_data:
            if not isinstance(pkt, dict):
                print(f"Lỗi: Phần tử trong packet_data không phải dictionary, kiểu dữ liệu: {type(pkt)}")
                continue
            src_ip = pkt.get("src_ip", "unknown")
            dst_ip = pkt.get("dst_ip", "unknown")
            hosts.add(src_ip)
            hosts.add(dst_ip)
            edges.append((src_ip, dst_ip))
        
        # Liệt kê các kết nối
        print("\nDanh sách các kết nối:")
        for i, (src, dst) in enumerate(set(edges), 1):  # Sử dụng set để loại bỏ kết nối trùng lặp
            print(f"Kết nối {i}: {src} <-> {dst}")
        
        return list(hosts), edges
    except Exception as e:
        print(f"Lỗi trong analyze_hosts: {str(e)}")
        return [], []

# Hàm thống kê giao thức và vẽ biểu đồ cột
def analyze_protocols(task_output):
    try:
        # Lấy dữ liệu từ task_output (có thể là TaskOutput object hoặc danh sách trực tiếp)
        if hasattr(task_output, 'raw_output'):
            packet_data = task_output.raw_output
        else:
            packet_data = task_output
        
        if not isinstance(packet_data, list):
            print(f"Lỗi: packet_data không phải là danh sách, kiểu dữ liệu: {type(packet_data)}")
            # Thử trích xuất lại từ file PCAP trực tiếp
            packet_data = extract_packet_info(pcap_file)
            if not isinstance(packet_data, list):
                sys.exit(1)
        
        protocols = []
        for pkt in packet_data:
            if not isinstance(pkt, dict):
                print(f"Lỗi: Phần tử trong packet_data không phải dictionary, kiểu dữ liệu: {type(pkt)}")
                continue
            protocols.append(pkt.get("protocol", "Unknown"))
        protocol_counts = Counter(protocols)
        
        # Liệt kê các giao thức và số lượng
        print("\nThống kê giao thức:")
        for proto, count in protocol_counts.items():
            print(f"{proto}: {count} gói tin")
        
        # Vẽ biểu đồ cột
        draw_protocol_bar(protocol_counts)
        
        return protocol_counts
    except Exception as e:
        print(f"Lỗi trong analyze_protocols: {str(e)}")
        return Counter()

# Hàm vẽ biểu đồ cột giao thức
def draw_protocol_bar(protocol_counts):
    protocols = list(protocol_counts.keys())
    counts = list(protocol_counts.values())
    
    plt.figure(figsize=(8, 6))
    plt.bar(protocols, counts, color='skyblue')
    plt.title("Packet Count by Protocol")
    plt.xlabel("Protocol")
    plt.ylabel("Number of Packets")
    plt.savefig('protocol_bar.png')
    print("Đã lưu biểu đồ cột 'protocol_bar.png'")

# Hàm vẽ biểu đồ mạng
def draw_network_graph(hosts, edges):
    try:
        G = nx.DiGraph()
        
        # Thêm các nút (hosts)
        for host in hosts:
            G.add_node(host)
        
        # Thêm các cạnh (kết nối)
        for src, dst in edges:
            G.add_edge(src, dst)
        
        # Vẽ biểu đồ
        plt.figure(figsize=(12, 10))
        pos = nx.spring_layout(G, seed=42)
        nx.draw(G, pos, with_labels=True, node_color='lightblue', 
                node_size=500, font_size=8, font_weight='bold', 
                arrows=True, arrowsize=15, edge_color='gray')
        plt.title("Network Connections Graph")
        plt.savefig('network_graph.png')
        print("Đã lưu biểu đồ mạng 'network_graph.png'")
        
        return True
    except Exception as e:
        print(f"Lỗi khi vẽ biểu đồ mạng: {str(e)}")
        return False

# Hàm xử lý yêu cầu visualization từ AI
def generate_visualization_code(task_output, packet_data, hosts, edges):
    try:
        # Lấy yêu cầu code từ AI agent hoặc sử dụng code mặc định dưới đây
        code_request = """
        def create_advanced_visualizations(packet_data, hosts, edges):
            import matplotlib.pyplot as plt
            import networkx as nx
            from collections import Counter
            import numpy as np
            
            # 1. Biểu đồ mạng lưới NetworkX
            plt.figure(figsize=(12, 10))
            G = nx.DiGraph()
            
            # Thêm các nút (hosts)
            for host in hosts:
                G.add_node(host)
            
            # Đếm số kết nối giữa các hosts
            edge_counts = Counter(edges)
            
            # Thêm các cạnh (kết nối) với độ dày tùy theo số lần xuất hiện
            for (src, dst), count in edge_counts.items():
                G.add_edge(src, dst, weight=count)
            
            # Vẽ biểu đồ
            pos = nx.spring_layout(G, seed=42)
            node_sizes = [300 + G.degree(node) * 100 for node in G.nodes()]
            
            # Vẽ các nút
            nx.draw_networkx_nodes(G, pos, node_color='lightblue', node_size=node_sizes, alpha=0.8)
            
            # Vẽ các cạnh với độ dày khác nhau
            edge_widths = [G[u][v]['weight'] * 0.5 for u, v in G.edges()]
            nx.draw_networkx_edges(G, pos, width=edge_widths, alpha=0.5, edge_color='gray', arrows=True, arrowsize=15)
            
            # Vẽ nhãn
            nx.draw_networkx_labels(G, pos, font_size=8, font_weight='bold')
            
            plt.title("Advanced Network Connections Graph")
            plt.axis('off')
            plt.savefig('advanced_network_graph.png', dpi=300, bbox_inches='tight')
            print("Đã lưu biểu đồ mạng nâng cao 'advanced_network_graph.png'")
            
            # 2. Biểu đồ phân bố giao thức dạng pie chart
            protocol_counts = Counter([pkt['protocol'] for pkt in packet_data])
            protocols = list(protocol_counts.keys())
            counts = list(protocol_counts.values())
            
            plt.figure(figsize=(10, 8))
            plt.pie(counts, labels=protocols, autopct='%1.1f%%', startangle=90, 
                    colors=plt.cm.tab10.colors[:len(protocols)], shadow=True)
            plt.axis('equal')
            plt.title('Protocol Distribution')
            plt.savefig('protocol_pie.png', dpi=300, bbox_inches='tight')
            print("Đã lưu biểu đồ tròn 'protocol_pie.png'")
            
            # 3. Biểu đồ nhiệt biểu thị các kết nối (heat map)
            unique_hosts = sorted(list(set(hosts)))
            n_hosts = len(unique_hosts)
            
            # Tạo ma trận kết nối
            connection_matrix = np.zeros((n_hosts, n_hosts))
            host_to_idx = {host: i for i, host in enumerate(unique_hosts)}
            
            for src, dst in edges:
                if src in host_to_idx and dst in host_to_idx:
                    src_idx = host_to_idx[src]
                    dst_idx = host_to_idx[dst]
                    connection_matrix[src_idx, dst_idx] += 1
            
            # Vẽ heatmap (giới hạn số host nếu quá nhiều)
            max_display = min(50, n_hosts)  # Giới hạn hiển thị tối đa 50 host
            plt.figure(figsize=(15, 12))
            plt.imshow(connection_matrix[:max_display, :max_display], cmap='YlOrRd')
            plt.colorbar(label='Number of Connections')
            
            # Hiển thị tên host nếu số lượng không quá lớn
            if max_display <= 30:
                plt.xticks(range(max_display), unique_hosts[:max_display], rotation=90, fontsize=8)
                plt.yticks(range(max_display), unique_hosts[:max_display], fontsize=8)
            
            plt.title('Host Connection Heatmap')
            plt.tight_layout()
            plt.savefig('connection_heatmap.png', dpi=300, bbox_inches='tight')
            print("Đã lưu bản đồ nhiệt 'connection_heatmap.png'")
            
            return True
        """
        
        # Thực thi code để tạo biểu đồ
        local_vars = {"packet_data": packet_data, "hosts": hosts, "edges": edges}
        exec(code_request, globals(), local_vars)
        
        # Gọi hàm trong code được tạo
        if 'create_advanced_visualizations' in local_vars:
            local_vars['create_advanced_visualizations'](packet_data, hosts, edges)
            
        return True
    except Exception as e:
        print(f"Lỗi khi tạo mã visualization: {str(e)}")
        return False

# Định nghĩa các Agent
packet_extractor = Agent(
    role="Packet Extractor",
    goal="Trích xuất thông tin gói tin từ file PCAP bao gồm IP và giao thức",
    backstory="Bạn là chuyên gia phân tích gói tin mạng. Nhiệm vụ của bạn là thực thi một quy trình để đọc và trích xuất dữ liệu chi tiết từ file PCAP đã được chỉ định cho tác vụ của bạn. Sau đó, bạn sẽ trình bày thông tin đã trích xuất.",
    verbose=True,
    llm="deepseek/deepseek-chat"
)

host_analyzer = Agent(
    role="Host Analyzer",
    goal="Đếm số host duy nhất và liệt kê các kết nối giữa IP nguồn và đích",
    backstory="Bạn là chuyên gia phân tích mạng, giỏi trong việc xác định host và liệt kê các kết nối giữa chúng.",
    verbose=True,
    llm="deepseek/deepseek-chat"
)

protocol_analyzer = Agent(
    role="Protocol Analyzer",
    goal="Thống kê số lượng gói tin theo giao thức, liệt kê các loại giao thức và số lượng, sau đó vẽ biểu đồ cột hiển thị phân bố giao thức",
    backstory="Bạn là chuyên gia phân tích giao thức mạng, có khả năng phân loại, đếm gói tin theo giao thức và trực quan hóa dữ liệu dưới dạng biểu đồ.",
    verbose=True,
    llm="deepseek/deepseek-chat"
)

visualization_agent = Agent(
    role="Visualization Expert",
    goal="Tạo các biểu đồ và trực quan hóa dữ liệu mạng nâng cao từ dữ liệu PCAP",
    backstory="Bạn là chuyên gia trực quan hóa dữ liệu mạng. Bạn có thể tạo các biểu đồ phức tạp và có ý nghĩa từ dữ liệu gói tin, giúp người dùng hiểu rõ hơn về cấu trúc mạng và dòng dữ liệu. Nhiệm vụ của bạn là tạo mã Python để vẽ biểu đồ từ dữ liệu đã phân tích.",
    verbose=True,
    llm="deepseek/deepseek-chat"
)

# Định nghĩa các Task
def create_tasks(pcap_file):
    extract_task = Task(
        description=f"Trích xuất thông tin IP nguồn, IP đích, và giao thức từ file PCAP '{pcap_file}'.",
        agent=packet_extractor,
        expected_output="Danh sách các gói tin với IP nguồn, IP đích, và giao thức.",
        output_file=None,
        callback=lambda output: extract_packet_info(pcap_file),
        raw_output=True
    )

    host_task = Task(
        description="Dựa trên danh sách gói tin, đếm số host duy nhất và liệt kê các kết nối giữa IP nguồn và đích.",
        agent=host_analyzer,
        expected_output="Số lượng host và danh sách các kết nối.",
        output_file=None,
        context=[extract_task],
        callback=lambda output: analyze_hosts(extract_task.output),
        raw_output=True
    )

    protocol_task = Task(
        description="Thống kê số lượng gói tin theo từng giao thức (TCP, UDP, ICMP, v.v.), liệt kê tất cả các loại giao thức cùng số lượng, và vẽ biểu đồ cột hiển thị phân bố giao thức.",
        agent=protocol_analyzer,
        expected_output="Bảng đếm số lượng gói tin theo giao thức và biểu đồ cột hiển thị phân bố giao thức.",
        output_file=None,
        context=[extract_task],
        callback=lambda output: analyze_protocols(extract_task.output),
        raw_output=True
    )
    
    visualization_task = Task(
        description="Tạo mã Python để vẽ biểu đồ mạng nâng cao và trực quan hóa dữ liệu từ các kết quả phân tích trước đó. Bao gồm: biểu đồ mạng lưới với NetworkX, biểu đồ tròn về phân bố giao thức, và bản đồ nhiệt về kết nối giữa các host.",
        agent=visualization_agent,
        expected_output="Mã Python để vẽ các biểu đồ trực quan về dữ liệu mạng và các file hình ảnh đã được lưu.",
        output_file=None,
        context=[extract_task, host_task, protocol_task],
        callback=lambda output: generate_visualization_code(output, 
                                   extract_packet_info(pcap_file),  # Trích xuất gói tin trực tiếp 
                                   *analyze_hosts(extract_packet_info(pcap_file))),  # Phân tích hosts trực tiếp
        raw_output=True
    )
    
    return [extract_task, host_task, protocol_task, visualization_task]

# Tạo Crew
def create_crew(pcap_file):
    return Crew(
        agents=[packet_extractor, host_analyzer, protocol_analyzer, visualization_agent],
        tasks=create_tasks(pcap_file),
        verbose=True
    )

# Chạy chương trình
def main():
    if len(sys.argv) == 2:
        pcap_file = sys.argv[1]
    else:
        print("Không phát hiện tham số dòng lệnh. Dùng mặc định: 'pcap_normal.pcap'")
        pcap_file = "pcap_normal.pcap"
    
    # Tạo và chạy Crew
    crew = create_crew(pcap_file)
    crew.kickoff()
    
    # Lấy kết quả từ các task (sửa để xử lý đúng kiểu dữ liệu)
    try:
        packet_data = extract_packet_info(pcap_file)  # Lấy dữ liệu trực tiếp
        hosts, edges = analyze_hosts(packet_data)
        protocol_counts = analyze_protocols(packet_data)
        
        # Vẽ biểu đồ mạng
        draw_network_graph(hosts, edges)
        
        # In kết quả host
        print(f"\nSố lượng host: {len(hosts)}")
        print(f"Danh sách host: {hosts}")
        
        print("\nPhân tích hoàn tất. Các biểu đồ đã được lưu trong thư mục hiện tại.")
    except Exception as e:
        print(f"Lỗi trong quá trình xử lý kết quả: {str(e)}")

if __name__ == "__main__":
    main()