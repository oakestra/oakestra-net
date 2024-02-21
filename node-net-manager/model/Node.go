package model

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"

	"github.com/jaypipes/ghw"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/load"
	"github.com/shirou/gopsutil/mem"
	psnet "github.com/shirou/gopsutil/net"

	"NetManager/logger"
)

const (
	CONTAINER_RUNTIME = "docker"
	UNIKERNEL_RUNTIME = "unikernel"
)

type Node struct {
	DiskInfo       map[string]string `json:"disk_info"`
	SystemInfo     map[string]string `json:"system_info"`
	GpuInfo        map[string]string `json:"gpu_info"`
	NetworkInfo    map[string]string `json:"network_info"`
	Host           string            `json:"host"`
	Ip             string            `json:"ip"`
	Ipv6           string            `json:"ipv6"`
	Id             string            `json:"id"`
	Technology     []string          `json:"technology"`
	Port           int               `json:"port"`
	MemoryMB       int               `json:"memory_free_in_MB"`
	MemoryUsed     float64           `json:"memory"`
	CpuCores       int               `json:"free_cores"`
	CpuUsage       float64           `json:"cpu"`
	NetManagerPort int
	Overlay        bool
}

var (
	once sync.Once
	node Node
)

func GetNodeInfo() Node {
	once.Do(func() {
		node = Node{
			Host:       getHostname(),
			SystemInfo: getSystemInfo(),
			CpuCores:   getCpuCores(),
			Port:       getPort(),
			Technology: getSupportedTechnologyList(),
			Overlay:    false,
		}
	})
	node.updateDynamicInfo()
	return node
}

func GetDynamicInfo() Node {
	node.updateDynamicInfo()
	return Node{
		CpuUsage:   node.CpuUsage,
		CpuCores:   node.CpuCores,
		MemoryUsed: node.MemoryUsed,
		MemoryMB:   node.MemoryMB,
	}
}

func EnableOverlay(port int) {
	node.Overlay = true
	node.NetManagerPort = port
}

func (n *Node) updateDynamicInfo() {
	n.CpuUsage = getAvgCpuUsage()
	n.Ip = getIp("4")
	n.Ipv6 = getIp("6")
	n.MemoryMB = getMemoryMB()
	n.MemoryUsed = getMemoryUsage()
	n.DiskInfo = getDiskinfo()
	n.NetworkInfo = getNetworkInfo()
	n.GpuInfo = getGpuInfo()
}

func SetNodeId(id string) {
	GetNodeInfo()
	node.Id = id
}

// @param: version, string ("4" or "6") depending on what IP address version to get
func getIp(version string) string {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, address := range addresses {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if version == "4" && ipnet.IP.To4() != nil {
				logger.InfoLogger().Println("Public IPv4: ", ipnet.IP.String())
				return ipnet.IP.String()
			}
			if version == "6" && ipnet.IP.To16() != nil && ipnet.IP.To4() == nil &&
				ipnet.IP.IsGlobalUnicast() &&
				!ipnet.IP.IsPrivate() {
				logger.InfoLogger().Println("Public IPv6: ", ipnet.IP.String())
				return ipnet.IP.String()
			}
		}
	}
	return ""
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = ""
		logger.ErrorLogger().Fatal("Unable to get Node hostname")
	}
	return hostname
}

func getSystemInfo() map[string]string {
	hostinfo, err := host.Info()
	if err != nil {
		logger.ErrorLogger().Printf("Error: %s", err.Error())
		return make(map[string]string, 0)
	}
	sysInfo := make(map[string]string)
	sysInfo["kernel_version"] = hostinfo.KernelVersion
	sysInfo["architecture"] = hostinfo.KernelArch
	sysInfo["os_version"] = hostinfo.OS
	sysInfo["uptime"] = strconv.Itoa(int(hostinfo.Uptime))
	sysInfo["full_stats"] = hostinfo.String()

	return sysInfo
}

func getCpuCores() int {
	cpu, err := cpu.Counts(true)
	if err != nil {
		logger.ErrorLogger().Printf("Error: %s", err.Error())
		return 0
	}
	return cpu
}

func getAvgCpuUsage() float64 {
	avg, err := load.Avg()
	if err != nil {
		return 100
	}
	return avg.Load5
}

func getMemoryMB() int {
	mem, err := mem.VirtualMemory()
	if err != nil {
		logger.ErrorLogger().Printf("Error: %s", err.Error())
		return 0
	}
	return int(mem.Free >> 20)
}

func getMemoryUsage() float64 {
	mem, err := mem.VirtualMemory()
	if err != nil {
		logger.ErrorLogger().Printf("Error: %s", err.Error())
		return 100
	}
	return mem.UsedPercent
}

func getDiskinfo() map[string]string {
	diskUsageStats, err := disk.Usage("/")
	diskInfoMap := make(map[string]string, 0)
	usage := "100"
	if err == nil {
		usage = strconv.Itoa(int(diskUsageStats.UsedPercent))
	}
	diskInfoMap["/"] = usage
	partitionsStats, err := disk.Partitions(true)
	if err == nil {
		for i, partition := range partitionsStats {
			diskInfoMap[fmt.Sprintf("partition_%d", i)] = partition.String()
		}
	}
	return diskInfoMap
}

func getGpuInfo() map[string]string {
	gpu, err := ghw.GPU()
	gpuInfoMap := make(map[string]string)
	if err != nil {
		fmt.Printf("Error %v", err)
		return gpuInfoMap
	}
	for i, card := range gpu.GraphicsCards {
		gpuInfoMap[fmt.Sprintf("gpu_%d", i)] = card.String()
	}
	return gpuInfoMap
}

func getNetworkInfo() map[string]string {
	netInfoMap := make(map[string]string)
	interfaces, err := psnet.Interfaces()
	if err == nil {
		for i, ifce := range interfaces {
			netInfoMap[fmt.Sprintf("interface_%d", i)] = ifce.String()
		}
	}
	return netInfoMap
}

func getPort() int {
	port := os.Getenv("MY_PORT")
	if port == "" {
		port = "3000"
	}
	ret, _ := strconv.Atoi(port)
	return ret
}

func getSupportedTechnologyList() []string {
	return []string{CONTAINER_RUNTIME}
}
