#include <iostream>
#include <vector>
#include "VendorIdent.cpp" //в разработке

using namespace std;

class Topology {
private:
	struct hop {
		string mac;
		string type;
		string vendor;
	};
	vector<hop> hops;

	struct edge {
		string h1;
		string h2;
		int weight;
	};
	vector<edge> graph;

	int add_mac(string mac) {
		if (mac == "")
			mac = "unspecified";

		for (int i = 0; i < hops.size(); i++)
			if (hops[i].mac == mac)
				return i;

		hop new_hop;
		new_hop.mac = mac;
		new_hop.type = "unkwnown";
		new_hop.vendor = "unkwnown";
		hops.push_back(new_hop);
		return hops.size() - 1;
	}

public:
	Topology() {
		hops.clear();
		graph.clear();
	}

	void add_pair(string mac_src, string mac_dst, string type) {
		add_mac(mac_src);
		add_mac(mac_dst);

		if (mac_src == "")
			mac_src = "unspecified";
		if (mac_dst == "")
			mac_dst = "unspecified";

		//search pair and return
		for (int i = 0; i < graph.size(); i++)
			if (graph[i].h1 == mac_src && graph[i].h2 == mac_dst)
			{
				graph[i].weight++;
				return;
			}

		//add new edge, if not found
		edge new_edge;
		new_edge.h1 = mac_src;
		new_edge.h2 = mac_dst;
		new_edge.weight = 1;
		graph.push_back(new_edge);
	}

	void set_type(string mac, string type) {
		if (mac != "")
		{
			int mac_id = 0;
			mac_id = add_mac(mac);
			hops[mac_id].type = type;
		}
	}

	void show_graph() {
		cout << "\n\nGraph(from\\to):\n\t";

		for (int i = 0; i < hops.size(); i++)
		{
			cout << "\t" << hops[i].mac;
		}
		cout << "\n";
		for (int i = 0; i < hops.size(); i++)
		{
			string curr_mac = hops[i].mac;
			cout << curr_mac;

			for (int j = 0; j < hops.size(); j++) {
				int num = 0;
				for (int k = 0; k < graph.size(); k++) {
					if (graph[k].h1 == hops[i].mac && graph[k].h2 == hops[j].mac)
						num = graph[k].weight;
				}
				cout << "\t" << num << "\t";
			}

			cout << "\n";
		}
	}

	void show_hops() {
		cout << "Mac addresses:\n";

		for (int i = 0; i < hops.size(); i++)
		{
			cout << "Mac: " << i + 1 << endl;
			cout << "\t mac: " << hops[i].mac << endl;
			cout << "\t type: " << hops[i].type << endl;
			cout << "\t vendor: " << hops[i].vendor << endl;
		}
	}
};
