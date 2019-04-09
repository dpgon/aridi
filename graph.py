from ipaddress import ip_address, ip_network


def makegraph(report):
    try:
        from graphviz import Graph
    except ImportError:
        report.log("INFO", "Graphviz is not installed. Please, "
                           "install it before with pip install graphviz")
        return False

    # Include IPs out of the local machine network segment?
    print("\nDo you want to draw all the infrastructure (a) or only the local machine "
          "network segment (s) infrastructure? (a/S) ", end="")
    ans = str(input()).lower().lstrip()

    if len(ans) > 0 and 'a' in ans[0]:
        all = True
    else:
        all = False

    # Create graph
    dot = Graph(comment='Network graph', filename='network.dot', engine='neato')

    dfgw = None
    gw = []
    subnet = []

    # Create subnets nodes
    for item in report.routes:
        if item[2] != "0.0.0.0":
            if item[0] == "0.0.0.0":
                dfgw = "gw{}".format(item[2])
            gw.append(item[2])
            dot.node("gw{}".format(item[2]),
                     "Gateway\n{}".format(item[2]),
                     shape="Mdiamond")
        if item[0] != "0.0.0.0" and item[0] != "169.254.0.0": # Exclude fallback network
            network = "{}/{}".format(item[0], item[1])
            subnet.append([network, item[3]])
            description = "     Network {}     ".format(network)
            dot.node(network, description, shape="octagon")

    # Link gw with subnets
    for item1 in gw:
        for item2 in subnet:
            if ip_address(item1) in ip_network(item2[0]):
                dot.edge("gw{}".format(item1), item2[0], arrowhead="none", len='8.00',)

    # Separe local machine and create local nodes
    localmachine = []
    for item in report.infrastructure_data:
        if "Local machine" in report.infrastructure_data[item]:
            localmachine.append(str(item))
        else:
            localrange = False
            for item2 in subnet:
                if item in ip_network(item2[0]) and str(item) not in gw:
                    dot.node(str(item), str(item), shape="ellipse")
                    dot.edge(str(item), item2[0], arrowhead="none", len='3.00')
                    localrange = True
            if not localrange and dfgw and all:
                dot.node(str(item), str(item), shape="ellipse")
                dot.edge(str(item), dfgw, arrowhead="none", len='5.00')

    # Draw local machine
    localname = "Scanned\nmachine\n"
    dot.node("localmachine", localname, shape="doublecircle")
    for item1 in localmachine:
        for item2 in subnet:
            if ip_address(item1) in ip_network(item2[0]):
                dot.edge("localmachine", item2[0], len='5.00',
                         arrowhead="none", label=item1, fontsize="10")

    dot.render(view=False)
    return True
