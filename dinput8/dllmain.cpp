#include <windows.h>
#include <string>
#include <fstream>
#include <vector>
#include <algorithm>
#include <cctype>

DWORD baseAddress = 0;
volatile bool g_running = true;
FILETIME g_lastConfigWrite = { 0, 0 };

// Door Override
const DWORD DOOR_INSTRUCTION_OFFSET = 0x56EFB;
const size_t DOOR_INSTRUCTION_SIZE = 5;
BYTE g_originalDoorBytes[DOOR_INSTRUCTION_SIZE] = { 0 };
bool g_isDoorNOPed = false;
bool g_originalBytesRead = false;
ULONGLONG g_dllAttachTime = 0;
const DWORD INITIAL_DELAY_MS = 5000;

struct CameraSettings {
    float playerFOV = 86.0f;
    float playerADSFOV = 70.0f;
    float playerCameraDistance = 2.5f;
    float playerFacingCameraDistance = 2.5f;
    bool doorOpenOverride = true;
    float doorFOV = 66.0f;
    float pushFOV = 86.0f;
    float pushCameraDistance = 2.5f;
    float maintenanceFOV = 86.0f;
    float maintenanceKickInFOVOffset = 0.0f;
    float maintenanceCameraDistance = 5.0f;
    float maintenanceKickInCameraDistanceOffset = 5.0f;
    float maintenanceSpeedToKickIn = 100.0f;
    float motorcycleFOV = 86.0f;
    float motorcycleKickInFOVOffset = 0.0f;
    float motorcycleCameraDistance = 5.0f;
    float motorcycleKickInCameraDistanceOffset = 5.0f;
    float motorcycleSpeedToKickIn = 100.0f;
    float ramsterBallFOV = 86.0f;
    float ramsterBallCameraDistance = 5.0f;
    float wheelchairFOV = 86.0f;
    float wheelchairCameraDistance = 2.5f;
    float uranusZoneBattleFOV = 86.0f;
    float uranusZoneBattleCameraDistance = 4.4f;
    float uranusZoneOutsideFOV = 86.0f;
} g_settings;

// Pointer definitions
#define PLAYER_FOV_BASE_POINTER 0x009E87C8
#define PLAYER_FOV_OFFSET 0x1B0
#define PLAYER_CAMERA_DISTANCE_OFFSET -0xE8
#define PLAYER_FACING_CAMERA_DISTANCE_DIRECT_OFFSET 0xCC
#define ADS_FOV_OFFSET_1 0xC
#define ADS_FOV_OFFSET_2 0xC
#define ADS_FOV_OFFSET_3 0xC
#define ADS_FOV_OFFSET_4 0x158
#define DOOR_FOV_BASE_POINTER 0x009E8E88
#define DOOR_FOV_OFFSET_1 0x68
#define DOOR_FOV_OFFSET_2 0xB4

// Maintenance Vehicle
#define MAINTENANCE_FOV_BASE_POINTER 0x009C16B0
#define MAINTENANCE_CAMERA_DISTANCE_RELATIVE_OFFSET 0x18
#define FOUR_WHEEL_KICK_IN_FOV_POINTER 0x009D2F28
#define FOUR_WHEEL_KICK_IN_SPEED_POINTER 0x009D2F28
#define FOUR_WHEEL_KICK_IN_CAM_DIST_POINTER 0x00A719E8

// Motorcycle
#define MOTORCYCLE_FOV_BASE_POINTER 0x009D2F28
#define MOTORCYCLE_CAMERA_DISTANCE_RELATIVE_OFFSET 0x18
#define TWO_WHEEL_KICK_IN_CAM_DIST_POINTER 0x009D2F28
#define TWO_WHEEL_KICK_IN_TIME_POINTER 0x009D2F28
#define TWO_WHEEL_KICK_IN_FOV_OFFSET_POINTER 0x009D2F28

// Push
#define PUSH_FOV_BASE_POINTER 0x009E87C8
#define PUSH_CAMERA_DISTANCE_OFFSET 0x18

// Ramster Ball
#define RAMSTER_BALL_FOV_BASE_POINTER 0x009D2F28
#define RAMSTER_BALL_CAMERA_DISTANCE_OFFSET 0x18

// Wheelchair
#define WHEELCHAIR_FOV_BASE_POINTER 0x00A719E8
#define WHEELCHAIR_CAMERA_DISTANCE_BASE_POINTER 0x00994C58

// Uranus Zone
#define URANUS_ZONE_BATTLE_CAM_DIST_BASE_POINTER 0x0098F494
#define OUTSIDE_FOV_BASE_POINTER 0x009E8E88
#define BATTLE_FOV_BASE_POINTER 0x00992A58

bool IsValidPointer(void* ptr, size_t size) {
    if (!ptr) return false;
    __try {
        volatile char dummy = *((char*)ptr);
        if (size > 1) dummy = *(((char*)ptr) + size - 1);
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool WriteProtectedMemory(void* address, const void* data, size_t size) {
    DWORD oldProtect;
    if (!VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &oldProtect)) return false;
    bool success = false;
    __try {
        memcpy(address, data, size);
        success = (memcmp(address, data, size) == 0);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        success = false;
    }
    VirtualProtect(address, size, oldProtect, &oldProtect);
    return success;
}

bool ForceWriteFloat(void* address, float value) {
    if (!IsValidPointer(address, sizeof(float))) return false;

    if (WriteProtectedMemory(address, &value, sizeof(float))) return true;

    DWORD oldProtect;
    if (VirtualProtect(address, sizeof(float), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        *(float*)address = value;
        VirtualProtect(address, sizeof(float), oldProtect, &oldProtect);
        return *(float*)address == value;
    }
    return false;
}

DWORD ResolvePointerChain(DWORD staticAddress, const std::vector<DWORD>& offsets) {
    DWORD currentAddress = baseAddress + staticAddress;

    if (!IsValidPointer((void*)currentAddress, sizeof(DWORD))) return 0;

    DWORD pointerValue = *(DWORD*)currentAddress;
    if (!pointerValue) return 0;

    currentAddress = pointerValue;

    for (size_t i = 0; i < offsets.size(); i++) {
        currentAddress += offsets[i];

        if (i == offsets.size() - 1) break;

        if (!IsValidPointer((void*)currentAddress, sizeof(DWORD))) return 0;

        DWORD nextPointer = *(DWORD*)currentAddress;
        if (!nextPointer) return 0;

        currentAddress = nextPointer;
    }
    return currentAddress;
}

std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(' ');
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(' ');
    return str.substr(first, (last - first + 1));
}

bool stringToBool(const std::string& str) {
    std::string s = trim(str);
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return (s == "true" || s == "1" || s == "on" || s == "yes");
}

void LoadConfig() {
    std::ifstream config("DLLMods\\OTRCustomizableCamera.txt");
    if (!config.is_open()) return;

    std::string line, currentSection;

    while (std::getline(config, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') {
            if (line.find("# Player") != std::string::npos) currentSection = "Player";
            else if (line.find("# Push") != std::string::npos) currentSection = "Push";
            else if (line.find("# 4 Wheeled Vehicles") != std::string::npos) currentSection = "4 Wheeled Vehicles";
            else if (line.find("# 2 Wheeled Vehicles") != std::string::npos) currentSection = "2 Wheeled Vehicles";
            else if (line.find("# Ramster Ball") != std::string::npos) currentSection = "Ramster Ball";
            else if (line.find("# Wheelchair") != std::string::npos) currentSection = "Wheelchair";
            else if (line.find("# Uranus Zone Battle") != std::string::npos) currentSection = "Uranus Zone Battle";
            continue;
        }

        size_t equalPos = line.find(" = ");
        if (equalPos == std::string::npos) continue;

        std::string key = trim(line.substr(0, equalPos));
        std::string valueStr = trim(line.substr(equalPos + 3));

        if (valueStr.empty()) continue;

        try {
            if (currentSection == "Player") {
                if (key == "FOV") g_settings.playerFOV = std::stof(valueStr);
                else if (key == "ADS FOV") g_settings.playerADSFOV = std::stof(valueStr);
                else if (key == "Camera Distance") g_settings.playerCameraDistance = std::stof(valueStr);
                else if (key == "Facing Camera Distance") g_settings.playerFacingCameraDistance = std::stof(valueStr);
                else if (key == "Door Override") g_settings.doorOpenOverride = stringToBool(valueStr);
                else if (key == "Door FOV") g_settings.doorFOV = std::stof(valueStr);
            }
            else if (currentSection == "Push") {
                if (key == "FOV") g_settings.pushFOV = std::stof(valueStr);
                else if (key == "Camera Distance") g_settings.pushCameraDistance = std::stof(valueStr);
            }
            else if (currentSection == "4 Wheeled Vehicles") {
                if (key == "FOV") g_settings.maintenanceFOV = std::stof(valueStr);
                else if (key == "Kick-In FOV Offset") g_settings.maintenanceKickInFOVOffset = std::stof(valueStr);
                else if (key == "Camera Distance") g_settings.maintenanceCameraDistance = std::stof(valueStr);
                else if (key == "Kick-In Camera Distance Offset") g_settings.maintenanceKickInCameraDistanceOffset = std::stof(valueStr);
                else if (key == "Speed to Kick-In") g_settings.maintenanceSpeedToKickIn = std::stof(valueStr);
            }
            else if (currentSection == "2 Wheeled Vehicles") {
                if (key == "FOV") g_settings.motorcycleFOV = std::stof(valueStr);
                else if (key == "Kick-In FOV Offset") g_settings.motorcycleKickInFOVOffset = std::stof(valueStr);
                else if (key == "Camera Distance") g_settings.motorcycleCameraDistance = std::stof(valueStr);
                else if (key == "Kick-In Camera Distance Offset") g_settings.motorcycleKickInCameraDistanceOffset = std::stof(valueStr);
                else if (key == "Speed to Kick-In") g_settings.motorcycleSpeedToKickIn = std::stof(valueStr);
            }
            else if (currentSection == "Ramster Ball") {
                if (key == "FOV") g_settings.ramsterBallFOV = std::stof(valueStr);
                else if (key == "Camera Distance") g_settings.ramsterBallCameraDistance = std::stof(valueStr);
            }
            else if (currentSection == "Wheelchair") {
                if (key == "FOV") g_settings.wheelchairFOV = std::stof(valueStr);
                else if (key == "Camera Distance") g_settings.wheelchairCameraDistance = std::stof(valueStr);
            }
            else if (currentSection == "Uranus Zone Battle") {
                if (key == "Battle FOV") g_settings.uranusZoneBattleFOV = std::stof(valueStr);
                else if (key == "Battle Camera Distance") g_settings.uranusZoneBattleCameraDistance = std::stof(valueStr);
                else if (key == "Outside FOV") g_settings.uranusZoneOutsideFOV = std::stof(valueStr);
            }
        }
        catch (...) {}
    }
    config.close();

    WIN32_FILE_ATTRIBUTE_DATA fileData;
    if (GetFileAttributesExA("DLLMods\\OTRCustomizableCamera.txt", GetFileExInfoStandard, &fileData)) {
        g_lastConfigWrite = fileData.ftLastWriteTime;
    }
}

bool HasConfigChanged() {
    WIN32_FILE_ATTRIBUTE_DATA fileData;
    if (GetFileAttributesExA("DLLMods\\OTRCustomizableCamera.txt", GetFileExInfoStandard, &fileData)) {
        return CompareFileTime(&fileData.ftLastWriteTime, &g_lastConfigWrite) != 0;
    }
    return false;
}

void UpdateCameraSettings() {
    if (!baseAddress) return;
    if (HasConfigChanged()) LoadConfig();

    // Door Override
    if (g_dllAttachTime != 0 && (GetTickCount64() - g_dllAttachTime >= INITIAL_DELAY_MS)) {
        DWORD doorAddr = baseAddress + DOOR_INSTRUCTION_OFFSET;
        if (!g_originalBytesRead) {
            if (IsValidPointer((void*)doorAddr, DOOR_INSTRUCTION_SIZE)) {
                memcpy(g_originalDoorBytes, (void*)doorAddr, DOOR_INSTRUCTION_SIZE);
                g_originalBytesRead = true;
            }
            if (!g_originalBytesRead) return;
        }

        if (IsValidPointer((void*)doorAddr, DOOR_INSTRUCTION_SIZE)) {
            if (g_settings.doorOpenOverride) {
                if (!g_isDoorNOPed) {
                    BYTE nopBytes[DOOR_INSTRUCTION_SIZE];
                    memset(nopBytes, 0x90, DOOR_INSTRUCTION_SIZE);
                    WriteProtectedMemory((void*)doorAddr, nopBytes, DOOR_INSTRUCTION_SIZE);
                    g_isDoorNOPed = true;
                }

                DWORD* doorFOVPtr = (DWORD*)(baseAddress + DOOR_FOV_BASE_POINTER);
                if (IsValidPointer(doorFOVPtr, sizeof(DWORD)) && *doorFOVPtr) {
                    DWORD addr = *doorFOVPtr;
                    if (IsValidPointer((void*)(addr + DOOR_FOV_OFFSET_1), sizeof(DWORD))) {
                        addr = *(DWORD*)(addr + DOOR_FOV_OFFSET_1);
                        if (IsValidPointer((void*)(addr + DOOR_FOV_OFFSET_2), sizeof(float))) {
                            ForceWriteFloat((void*)(addr + DOOR_FOV_OFFSET_2), g_settings.doorFOV);
                        }
                    }
                }
            }
            else if (g_isDoorNOPed) {
                WriteProtectedMemory((void*)doorAddr, g_originalDoorBytes, DOOR_INSTRUCTION_SIZE);
                g_isDoorNOPed = false;
            }
        }
    }

    // Player FOV
    DWORD* playerPtr = (DWORD*)(baseAddress + PLAYER_FOV_BASE_POINTER);
    if (IsValidPointer(playerPtr, sizeof(DWORD)) && *playerPtr) {
        float* fovPtr = (float*)(*playerPtr + PLAYER_FOV_OFFSET);
        ForceWriteFloat(fovPtr, g_settings.playerFOV);
        ForceWriteFloat((void*)((DWORD)fovPtr + PLAYER_CAMERA_DISTANCE_OFFSET), g_settings.playerCameraDistance);
        ForceWriteFloat((void*)(*playerPtr + PLAYER_FACING_CAMERA_DISTANCE_DIRECT_OFFSET), g_settings.playerFacingCameraDistance);

        // ADS FOV
        DWORD addr = *playerPtr;
        if (IsValidPointer((void*)(addr + ADS_FOV_OFFSET_1), sizeof(DWORD))) {
            addr = *(DWORD*)(addr + ADS_FOV_OFFSET_1);
            if (IsValidPointer((void*)(addr + ADS_FOV_OFFSET_2), sizeof(DWORD))) {
                addr = *(DWORD*)(addr + ADS_FOV_OFFSET_2);
                if (IsValidPointer((void*)(addr + ADS_FOV_OFFSET_3), sizeof(DWORD))) {
                    addr = *(DWORD*)(addr + ADS_FOV_OFFSET_3);
                    if (IsValidPointer((void*)(addr + ADS_FOV_OFFSET_4), sizeof(float))) {
                        ForceWriteFloat((void*)(addr + ADS_FOV_OFFSET_4), g_settings.playerADSFOV);
                    }
                }
            }
        }
    }

    // Maintenance Vehicle
    DWORD maintenanceAddr = ResolvePointerChain(MAINTENANCE_FOV_BASE_POINTER, { 0x224, 0x7C, 0xF0, 0xC, 0xC, 0x3E8 });
    if (maintenanceAddr) {
        ForceWriteFloat((void*)maintenanceAddr, g_settings.maintenanceFOV);
        ForceWriteFloat((void*)(maintenanceAddr + MAINTENANCE_CAMERA_DISTANCE_RELATIVE_OFFSET), g_settings.maintenanceCameraDistance);
    }

    // 4-Wheel Kick-In
    DWORD kickInFOVAddr = ResolvePointerChain(FOUR_WHEEL_KICK_IN_FOV_POINTER, { 0x18, 0x12C, 0x26C, 0xC, 0x26C, 0x438 });
    if (kickInFOVAddr) ForceWriteFloat((void*)kickInFOVAddr, g_settings.maintenanceKickInFOVOffset);

    DWORD kickInSpeedAddr = ResolvePointerChain(FOUR_WHEEL_KICK_IN_SPEED_POINTER, { 0x14, 0x24C, 0xC, 0x26C, 0x26C, 0x424 });
    if (kickInSpeedAddr) ForceWriteFloat((void*)kickInSpeedAddr, g_settings.maintenanceSpeedToKickIn);

    DWORD kickInCamAddr = ResolvePointerChain(FOUR_WHEEL_KICK_IN_CAM_DIST_POINTER, { 0x174, 0x14, 0x24C, 0x26C, 0x4CC, 0x404 });
    if (kickInCamAddr) ForceWriteFloat((void*)kickInCamAddr, g_settings.maintenanceKickInCameraDistanceOffset);

    // Motorcycle
    DWORD motorcycleAddr = ResolvePointerChain(MOTORCYCLE_FOV_BASE_POINTER, { 0x1C, 0xC, 0xC, 0x8A8 });
    if (motorcycleAddr) {
        ForceWriteFloat((void*)motorcycleAddr, g_settings.motorcycleFOV);
        ForceWriteFloat((void*)(motorcycleAddr + MOTORCYCLE_CAMERA_DISTANCE_RELATIVE_OFFSET), g_settings.motorcycleCameraDistance);
    }

    // 2-Wheel Kick-In
    DWORD motoKickCamAddr = ResolvePointerChain(TWO_WHEEL_KICK_IN_CAM_DIST_POINTER, { 0x14, 0xC, 0x12C, 0xC, 0x8C4 });
    if (motoKickCamAddr) ForceWriteFloat((void*)motoKickCamAddr, g_settings.motorcycleKickInCameraDistanceOffset);

    DWORD motoKickTimeAddr = ResolvePointerChain(TWO_WHEEL_KICK_IN_TIME_POINTER, { 0x10, 0x8, 0x100, 0x36C, 0xB44 });
    if (motoKickTimeAddr) ForceWriteFloat((void*)motoKickTimeAddr, g_settings.motorcycleSpeedToKickIn);

    DWORD motoKickFOVAddr = ResolvePointerChain(TWO_WHEEL_KICK_IN_FOV_OFFSET_POINTER, { 0xC, 0x1D0, 0x10, 0x36C, 0xB58 });
    if (motoKickFOVAddr) ForceWriteFloat((void*)motoKickFOVAddr, g_settings.motorcycleKickInFOVOffset);

    // Push
    DWORD pushAddr = ResolvePointerChain(PUSH_FOV_BASE_POINTER, { 0xC, 0x74, 0xF8, 0x90, 0x11C, 0xA0, 0x274 });
    if (pushAddr) {
        ForceWriteFloat((void*)pushAddr, g_settings.pushFOV);
        ForceWriteFloat((void*)(pushAddr + PUSH_CAMERA_DISTANCE_OFFSET), g_settings.pushCameraDistance);
    }

    // Ramster Ball
    DWORD ramsterAddr = ResolvePointerChain(RAMSTER_BALL_FOV_BASE_POINTER, { 0x14, 0xB0, 0x10, 0x24C, 0x26C, 0x4CC, 0x648 });
    if (ramsterAddr) {
        ForceWriteFloat((void*)ramsterAddr, g_settings.ramsterBallFOV);
        ForceWriteFloat((void*)(ramsterAddr + RAMSTER_BALL_CAMERA_DISTANCE_OFFSET), g_settings.ramsterBallCameraDistance);
    }

    // Wheelchair
    DWORD wheelchairFOVAddr = ResolvePointerChain(WHEELCHAIR_FOV_BASE_POINTER, { 0xBC, 0x970, 0x14, 0x14, 0x84, 0xF68 });
    if (wheelchairFOVAddr) ForceWriteFloat((void*)wheelchairFOVAddr, g_settings.wheelchairFOV);

    DWORD wheelchairCamAddr = ResolvePointerChain(WHEELCHAIR_CAMERA_DISTANCE_BASE_POINTER, { 0x3C, 0x88, 0x88, 0x8, 0x60, 0xF80 });
    if (wheelchairCamAddr) ForceWriteFloat((void*)wheelchairCamAddr, g_settings.wheelchairCameraDistance);

    // Uranus Zone
    DWORD uranusCamAddr = ResolvePointerChain(URANUS_ZONE_BATTLE_CAM_DIST_BASE_POINTER, { 0x41C, 0x88, 0x8, 0x60, 0x440, 0xAA8 });
    if (uranusCamAddr) ForceWriteFloat((void*)uranusCamAddr, g_settings.uranusZoneBattleCameraDistance);

    DWORD outsideFOVAddr = ResolvePointerChain(OUTSIDE_FOV_BASE_POINTER, { 0x88, 0x8, 0x60, 0x440, 0x220, 0x6A0 });
    if (outsideFOVAddr) ForceWriteFloat((void*)outsideFOVAddr, g_settings.uranusZoneOutsideFOV);

    DWORD battleFOVAddr = ResolvePointerChain(BATTLE_FOV_BASE_POINTER, { 0x8, 0x60, 0x440, 0x0, 0x5EC, 0x98, 0x2F0 });
    if (battleFOVAddr) ForceWriteFloat((void*)battleFOVAddr, g_settings.uranusZoneBattleFOV);
}

DWORD WINAPI MonitorThreadProc(LPVOID lpParam) {
    CreateDirectoryA("DLLMods", NULL);
    LoadConfig();
    while (g_running) {
        UpdateCameraSettings();
        Sleep(100);
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        baseAddress = (DWORD)GetModuleHandle(NULL);
        g_dllAttachTime = GetTickCount64();
        CreateThread(NULL, 0, MonitorThreadProc, NULL, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        g_running = false;
        if (g_isDoorNOPed) {
            DWORD doorAddr = baseAddress + DOOR_INSTRUCTION_OFFSET;
            if (IsValidPointer((void*)doorAddr, DOOR_INSTRUCTION_SIZE)) {
                WriteProtectedMemory((void*)doorAddr, g_originalDoorBytes, DOOR_INSTRUCTION_SIZE);
            }
        }
        break;
    }
    return TRUE;
}