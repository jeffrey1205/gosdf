// Package integration 在真实 SoftSDF 设备(testdata/softsdf)上端到端验证
// gosdf 的导出接口:覆盖除 probe 外全部导出接口,probe 由 TestProbeSoftSDF 覆盖;
// 密钥文件由 softsdfinit 生成到临时目录,进程 CWD
// 指向该目录(SoftSDF 按相对路径读取),全包共享唯一设备句柄。
package integration
