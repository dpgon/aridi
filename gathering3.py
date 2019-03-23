import traceback
from style import detailheader, detailfile


def _getram(precheck):
    detail = detailheader("Memory information")
    sum = "Current memory status:\n"
    if precheck.shouldread("/proc/meminfo"):
        meminfo = {}

        with open("/proc/meminfo") as f:
            info = f.readlines()

        for item in info:
            if ":" in item:
                name = item.split(":")[0].strip()
                data = item.split(":")[1].strip()
                if "memtotal" in name.lower():
                    meminfo["memtotal"] = round(int(data.split(" ")[0])/1024)
                if "memfree" in name.lower():
                    meminfo["memfree"] = round(int(data.split(" ")[0])/1024)
                if "memavailable" in name.lower():
                    meminfo["memavailable"] = round(int(data.split(" ")[0])/1024)
                if "buffers" in name.lower():
                    meminfo["buffers"] = round(int(data.split(" ")[0])/1024)
                if "cached"==name.lower():
                    meminfo["cached"] = round(int(data.split(" ")[0])/1024)
                if "swapcached" in name.lower():
                    meminfo["swapcache"] = round(int(data.split(" ")[0])/1024)
                if "swaptotal" in name.lower():
                    meminfo["swaptotal"] = round(int(data.split(" ")[0])/1024)
                if "swapfree" in name.lower():
                    meminfo["swapfree"] = round(int(data.split(" ")[0])/1024)
                if "hardwarecorrupted" in name.lower():
                    meminfo["hardwarecorrupted"] = round(int(data.split(" ")[0])/1024)
                if "slab"==name.lower():
                    meminfo["slab"] = round(int(data.split(" ")[0])/1024)

        meminfo["totalused"] = meminfo.get("memtotal", 0) - meminfo.get("memfree", 0)
        meminfo["buff/cache"] = meminfo.get("buffers", 0) + meminfo.get("cached", 0) + \
                                meminfo.get("slab", 0)
        meminfo["reallyused"] = meminfo["totalused"] - meminfo["buff/cache"]
        meminfo["%used"] = round(meminfo["reallyused"] * 100 / meminfo.get("memtotal"))
        meminfo["%buff/cache"] = round(meminfo["buff/cache"] * 100 / meminfo.get("memtotal"))
        meminfo["%free"] = round(meminfo.get("memfree", 0) * 100 / meminfo.get("memtotal"))

        if meminfo.get("swaptotal"):
            meminfo["swapused"] = meminfo.get("swaptotal", 0) - meminfo.get("swapfree", 0)
            meminfo["%swapused"] = round(meminfo["swapused"] * 100 / meminfo.get("swaptotal"))
            meminfo["%swapfree"] = round(meminfo.get("swapfree", 0) * 100 / meminfo.get("swaptotal"))

        sum += " |__Total memory of {} MB\n".format(meminfo.get("memtotal", 0 ))
        sum += " |       |__{}% used\n".format(meminfo["%used"])
        sum += " |       |__{}% buffers/cache\n".format(meminfo["%buff/cache"])
        sum += " |       |__{}% free\n".format(meminfo["%free"])
        sum += " |__Total SWAP of {} MB\n".format(meminfo.get("swaptotal", 0))

        if meminfo.get("swaptotal"):
            sum += "         |__{}% used\n".format(meminfo["%swapused"])
            sum += "         |__{}% free\n".format(meminfo["%swapfree"])

        detail += sum
        detail += "\nDetailed memory status:\n"
        detail += " |__Total memory:       {} MB\n".format(meminfo.get("memtotal", 0))
        detail += " |__Memory used:        {} MB\n".format(meminfo["totalused"])
        detail += " |__Memory really used: {} MB\n".format(meminfo["reallyused"])
        detail += " |__Free memory:        {} MB\n".format(meminfo.get("memfree", 0))
        detail += " |__Available memory:   {} MB\n".format(meminfo.get("memavailable", 0))
        detail += " |__Buffers:            {} MB\n".format(meminfo.get("buffers", 0))
        detail += " |__Cached:             {} MB\n".format(meminfo.get("cached", 0))
        detail += " |__Slab:               {} MB\n".format(meminfo.get("slab", 0))
        detail += " |__Buff/Cache/Slab:    {} MB\n".format(meminfo["buff/cache"])
        detail += " |__Hardware corrupted: {} MB\n".format(meminfo.get("hardwarecorrupted", 0))

        if meminfo.get("swaptotal"):
            detail += " |__Total swap:         {} MB\n".format(meminfo.get("swaptotal", 0))
            detail += " |__Free swap:          {} MB\n".format(meminfo.get("swapfree", 0))
            detail += " |__Used swap:          {} MB\n".format(meminfo["swapused"])
            detail += " |__Cached swap:        {} MB\n".format(meminfo["swapcache"])

        return sum, detail


def getvolatileinfo(report, precheck):
    # Get RAM live reports
    try:
        report.log("DEBUG", "RAM live information gathering started")
        sum, detail = _getram(precheck)
        report.summarized(3, sum)
        report.detailed(3, detail)
        report.log("DEBUG", "RAM live information completed")
    except Exception as e:
        report.log("ERROR", "Can't obtain RAM live information")
        report.log("DEBUG", str(e))
        report.log("DEBUG", traceback.format_exc())