#include <iostream>
#include <fstream>
#include <vector>
#include <set>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <curl/curl.h>
#include <magic.h>
#include <capstone/capstone.h>
#include <unistd.h>
#include <map>
#include <graphviz/cgraph.h>
#include <graphviz/gvc.h>


#define RESET   "\033[0m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN    "\033[36m"
#define WHITE   "\033[37m"


struct Settings {
    cs_arch arch = CS_ARCH_X86;
    cs_mode mode = CS_MODE_32;
    uint64_t start_address = 0x1000;
    std::set<std::string> ignoreMnemonics = {"add", "sub", "inc", "dec", "cmp", "and", "or", "xor"};
    std::string output_file = "";
    uint64_t address_range_start = 0;
    uint64_t address_range_end = 0;
    bool show_bytes = true;
    bool show_mnemonics = true;
    bool show_operands = true;
};

// База данных с описаниями инструкций
std::map<std::string, std::pair<std::string, bool>> instructionDescriptions = {
    {"add", {"Сложение источника и назначения", false}},
    {"sub", {"Вычитание источника из назначения", false}},
    {"mul", {"Умножение (без знака)", false}},
    {"div", {"Деление (без знака)", true}}, // Опасная инструкция
    {"imul", {"Умножение (со знаком)", false}},
    {"idiv", {"Деление (со знаком)", true}}, // Опасная инструкция
    {"inc", {"Увеличение значения на единицу", false}},
    {"dec", {"Уменьшение значения на единицу", false}},
    {"and", {"Логическое И", false}},
    {"or", {"Логическое ИЛИ", false}},
    {"xor", {"Логическое исключающее ИЛИ", false}},
    {"not", {"Логическое отрицание", false}},
    {"neg", {"Арифметическое отрицание", false}},
    {"mov", {"Копирование данных из источника в назначение", false}},
    {"lea", {"Загрузка адреса эффективного адреса", false}},
    {"cmp", {"Сравнение двух операндов", false}},
    {"test", {"Логическое И двух операндов, устанавливая флаги", false}},
    {"jmp", {"Безусловный переход", true}}, // Опасная инструкция
    {"je", {"Переход, если равно (ZF=1)", true}}, // Опасная инструкция
    {"jne", {"Переход, если не равно (ZF=0)", true}}, // Опасная инструкция
    {"jl", {"Переход, если меньше (signed)", true}}, // Опасная инструкция
    {"jle", {"Переход, если меньше или равно (signed)", true}}, // Опасная инструкция
    {"jg", {"Переход, если больше (signed)", true}}, // Опасная инструкция
    {"jge", {"Переход, если больше или равно (signed)", true}}, // Опасная инструкция
    {"jb", {"Переход, если ниже (unsigned)", true}}, // Опасная инструкция
    {"jbe", {"Переход, если ниже или равно (unsigned)", true}}, // Опасная инструкция
    {"ja", {"Переход, если выше (unsigned)", true}}, // Опасная инструкция
    {"jae", {"Переход, если выше или равно (unsigned)", true}}, // Опасная инструкция
    {"call", {"Вызов функции", true}}, // Опасная инструкция
    {"ret", {"Возврат из функции", true}}, // Опасная инструкция
    {"push", {"Помещение значения в стек", false}},
    {"pop", {"Извлечение значения из стека", false}},
    {"nop", {"Нет операции", false}},
    {"hlt", {"Остановка процессора до прерывания", true}}, // Опасная инструкция
    {"clc", {"Сброс флага переноса", false}},
    {"stc", {"Установка флага переноса", false}},
    {"cli", {"Запрет прерываний", true}}, // Опасная инструкция
    {"sti", {"Разрешение прерываний", true}}, // Опасная инструкция
    {"cld", {"Сброс флага направления", false}},
    {"std", {"Установка флага направления", false}},
    {"movzx", {"Копирование с расширением нуля", false}},
    {"movsx", {"Копирование с расширением знака", false}},
    {"shl", {"Логический сдвиг влево", false}},
    {"shr", {"Логический сдвиг вправо", false}},
    {"sal", {"Арифметический сдвиг влево", false}},
    {"sar", {"Арифметический сдвиг вправо", false}},
    {"rol", {"Ротация влево", false}},
    {"ror", {"Ротация вправо", false}},
    {"rcl", {"Ротация через перенос влево", false}},
    {"rcr", {"Ротация через перенос вправо", false}},
    {"bsf", {"Нахождение первого установленного бита (с младшего бита)", false}},
    {"bsr", {"Нахождение первого установленного бита (со старшего бита)", false}},
    {"bt", {"Проверка бита", false}},
    {"bts", {"Установка бита", false}},
    {"btr", {"Сброс бита", false}},
    {"btc", {"Инвертирование бита", false}},
    {"cmova", {"Перемещение, если выше (unsigned)", false}},
    {"cmovb", {"Перемещение, если ниже (unsigned)", false}},
    {"cmovg", {"Перемещение, если больше (signed)", false}},
    {"cmovl", {"Перемещение, если меньше (signed)", false}},
    {"cmove", {"Перемещение, если равно", false}},
    {"cmovne", {"Перемещение, если не равно", false}},
    {"sete", {"Установить байт, если равно", false}},
    {"setne", {"Установить байт, если не равно", false}},
    {"setl", {"Установить байт, если меньше (signed)", false}},
    {"setle", {"Установить байт, если меньше или равно (signed)", false}},
    {"setg", {"Установить байт, если больше (signed)", false}},
    {"setge", {"Установить байт, если больше или равно (signed)", false}},
    {"setb", {"Установить байт, если ниже (unsigned)", false}},
    {"setbe", {"Установить байт, если ниже или равно (unsigned)", false}},
    {"seta", {"Установить байт, если выше (unsigned)", false}},
    {"setae", {"Установить байт, если выше или равно (unsigned)", false}},
    {"movd", {"Перемещение данных (MMX/SSE)", false}},
    {"movq", {"Перемещение квадро-слова (MMX/SSE)", false}},
    {"movaps", {"Перемещение регистров XMM (SSE)", false}},
    {"movups", {"Перемещение нерегулярных регистров XMM (SSE)", false}},
    {"addps", {"Сложение чисел с плавающей запятой (SSE)", false}},
    {"subps", {"Вычитание чисел с плавающей запятой (SSE)", false}},
    {"mulps", {"Умножение чисел с плавающей запятой (SSE)", false}},
    {"divps", {"Деление чисел с плавающей запятой (SSE)", true}}, // Опасная инструкция
    {"sqrtps", {"Извлечение квадратного корня (SSE)", false}},
    {"maxps", {"Максимум чисел с плавающей запятой (SSE)", false}},
    {"minps", {"Минимум чисел с плавающей запятой (SSE)", false}},
    {"andps", {"Логическое И для чисел с плавающей запятой (SSE)", false}},
    {"orps", {"Логическое ИЛИ для чисел с плавающей запятой (SSE)", false}},
    {"xorps", {"Логическое исключающее ИЛИ для чисел с плавающей запятой (SSE)", false}},
    {"addpd", {"Сложение чисел с плавающей запятой двойной точности (SSE2)", false}},
    {"subpd", {"Вычитание чисел с плавающей запятой двойной точности (SSE2)", false}},
    {"mulpd", {"Умножение чисел с плавающей запятой двойной точности (SSE2)", false}},
    {"divpd", {"Деление чисел с плавающей запятой двойной точности (SSE2)", true}}, // Опасная инструкция
    {"sqrtpd", {"Извлечение квадратного корня двойной точности (SSE2)", false}},
    {"maxpd", {"Максимум чисел с плавающей запятой двойной точности (SSE2)", false}},
    {"minpd", {"Минимум чисел с плавающей запятой двойной точности (SSE2)", false}},
    {"andpd", {"Логическое И для чисел с плавающей запятой двойной точности (SSE2)", false}},
    {"orpd", {"Логическое ИЛИ для чисел с плавающей запятой двойной точности (SSE2)", false}},
    {"xorpd", {"Логическое исключающее ИЛИ для чисел с плавающей запятой двойной точности (SSE2)", false}}
};


std::string getInstructionDescription(const std::string &mnemonic) {
    auto it = instructionDescriptions.find(mnemonic);
    if (it != instructionDescriptions.end()) {
        return it->second.first;
    }
    return "Описание не найдено";
}


bool isInstructionDangerous(const std::string &mnemonic) {
    auto it = instructionDescriptions.find(mnemonic);
    if (it != instructionDescriptions.end()) {
        return it->second.second;
    }
    return false;
}


void printBanner() {
    std::cout << CYAN << R"(
   ____   ____  _   _  _____ 
  / __ \ / __ \| \ | |/ ____|
 | |  | | |  | |  \| | |  __ 
 | |  | | |  | | . ` | | |_ |
 | |__| | |__| | |\  | |__| |
  \____/ \____/|_| \_|\_____|
)" << RESET << std::endl;
}

std::vector<uint8_t> readBinaryFile(const std::string &filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << RED << "Unable to open file: " << filePath << RESET << std::endl;
        return {};
    }

    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(fileSize);
    file.read(reinterpret_cast<char*>(buffer.data()), fileSize);
    return buffer;
}


std::vector<uint8_t> downloadFile(const std::string& url) {
    CURL *curl;
    CURLcode res;
    std::vector<uint8_t> data;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](void* ptr, size_t size, size_t nmemb, void* userdata) {
            auto data = static_cast<std::vector<uint8_t>*>(userdata);
            data->insert(data->end(), static_cast<uint8_t*>(ptr), static_cast<uint8_t*>(ptr) + size * nmemb);
            return size * nmemb;
        });
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
    }
    return data;
}


void printInstruction(const cs_insn &insn, const Settings &settings) {
    if (insn.address < settings.address_range_start || (settings.address_range_end != 0 && insn.address > settings.address_range_end)) {
        return;
    }

   
    std::cout << GREEN << "0x" << std::hex << std::setw(8) << std::setfill('0') << insn.address << RESET << ":\t";

    
    if (settings.show_bytes) {
        std::cout << MAGENTA;
        for (size_t j = 0; j < insn.size; j++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(insn.bytes[j]) << " ";
        }
        std::cout << RESET;
    }

    
    if (settings.show_mnemonics) {
        std::cout << YELLOW << std::setw(7) << std::left << insn.mnemonic << RESET << "\t";
    }
    if (settings.show_operands) {
        std::cout << BLUE << insn.op_str << RESET << std::endl;
    }

    
    std::string description = getInstructionDescription(insn.mnemonic);
    std::cout << WHITE << description << RESET << std::endl;
}


void disassemble(const std::vector<uint8_t> &code, const Settings &settings, std::vector<cs_insn> &instructions) {
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(settings.arch, settings.mode, &handle) != CS_ERR_OK) {
        std::cerr << RED << "Failed to initialize Capstone" << RESET << std::endl;
        return;
    }

    count = cs_disasm(handle, code.data(), code.size(), settings.start_address, 0, &insn);
    if (count > 0) {
        for (size_t i = 0; i < count; i++) {
           
            if (settings.ignoreMnemonics.find(insn[i].mnemonic) != settings.ignoreMnemonics.end()) {
                continue;
            }
            instructions.push_back(insn[i]);
            printInstruction(insn[i], settings);
        }
        cs_free(insn, count);
    } else {
        std::cerr << RED << "Failed to disassemble given code!" << RESET << std::endl;
    }

    cs_close(&handle);
}

void printSupportedArchitectures() {
    std::cout << "Supported architectures:\n";
    std::cout << "CS_ARCH_X86: " << CS_ARCH_X86 << "\n";
    std::cout << "CS_ARCH_ARM: " << CS_ARCH_ARM << "\n";
    std::cout << "CS_ARCH_ARM64: " << CS_ARCH_ARM64 << "\n";
    std::cout << "CS_ARCH_MIPS: " << CS_ARCH_MIPS << "\n";
    std::cout << "CS_ARCH_PPC: " << CS_ARCH_PPC << "\n";
    std::cout << "CS_ARCH_SPARC: " << CS_ARCH_SPARC << "\n";
    std::cout << "CS_ARCH_SYSZ: " << CS_ARCH_SYSZ << "\n";
    std::cout << "CS_ARCH_XCORE: " << CS_ARCH_XCORE << "\n";
}


void printSupportedModes() {
    std::cout << "Supported modes:\n";
    std::cout << "CS_MODE_LITTLE_ENDIAN: " << CS_MODE_LITTLE_ENDIAN << "\n";
    std::cout << "CS_MODE_ARM: " << CS_MODE_ARM << "\n";
    std::cout << "CS_MODE_THUMB: " << CS_MODE_THUMB << "\n";
    std::cout << "CS_MODE_MCLASS: " << CS_MODE_MCLASS << "\n";
    std::cout << "CS_MODE_V8: " << CS_MODE_V8 << "\n";
    std::cout << "CS_MODE_MICRO: " << CS_MODE_MICRO << "\n";
    std::cout << "CS_MODE_MIPS3: " << CS_MODE_MIPS3 << "\n";
    std::cout << "CS_MODE_MIPS32R6: " << CS_MODE_MIPS32R6 << "\n";
    std::cout << "CS_MODE_MIPS2: " << CS_MODE_MIPS2 << "\n";
}


bool autoDetectArchitectureAndMode(const std::string &filePath, Settings &settings) {
    magic_t magic = magic_open(MAGIC_NONE);
    if (magic == nullptr) {
        std::cerr << RED << "Unable to initialize libmagic" << RESET << std::endl;
        return false;
    }

    if (magic_load(magic, nullptr) != 0) {
        std::cerr << RED << "Cannot load magic database: " << magic_error(magic) << RESET << std::endl;
        magic_close(magic);
        return false;
    }

    const char *magic_result = magic_file(magic, filePath.c_str());
    if (magic_result == nullptr) {
        std::cerr << RED << "Cannot analyze file: " << magic_error(magic) << RESET << std::endl;
        magic_close(magic);
        return false;
    }

    std::string result(magic_result);
    std::cout << BLUE << "File analysis result: " << result << RESET << std::endl;

   
    if (result.find("x86-64") != std::string::npos) {
        settings.arch = CS_ARCH_X86;
        settings.mode = CS_MODE_64;
    } else if (result.find("80386") != std::string::npos) {
        settings.arch = CS_ARCH_X86;
        settings.mode = CS_MODE_32;
    } else if (result.find("ARM") != std::string::npos) {
        settings.arch = CS_ARCH_ARM;
        settings.mode = (result.find("64-bit") != std::string::npos) ? CS_MODE_ARM : CS_MODE_THUMB;
    } else if (result.find("AArch64") != std::string::npos) {
        settings.arch = CS_ARCH_ARM64;
        settings.mode = CS_MODE_ARM;
    } else {
        std::cerr << RED << "Unsupported architecture" << RESET << std::endl;
        magic_close(magic);
        return false;
    }

    magic_close(magic);
    return true;
}


void getSettingsFromUser(Settings &settings, std::string &filePath) {
    std::cout << CYAN << "Выберите бинарный файл из текущей директории: " << RESET << std::endl;

    std::vector<std::filesystem::path> files;
    for (const auto& entry : std::filesystem::directory_iterator(".")) {
        if (entry.is_regular_file()) {
            files.push_back(entry.path());
        }
    }

    for (size_t i = 0; i < files.size(); ++i) {
        std::cout << i + 1 << ": " << files[i].string() << std::endl;
    }

    size_t fileIndex;
    std::cout << CYAN << "Введите номер файла: " << RESET;
    std::cin >> fileIndex;

    if (fileIndex < 1 || fileIndex > files.size()) {
        std::cerr << RED << "Неправильный номер файла!" << RESET << std::endl;
        return;
    }

    filePath = files[fileIndex - 1].string();

    if (!autoDetectArchitectureAndMode(filePath, settings)) {
        std::cerr << RED << "Failed to auto-detect architecture and mode" << RESET << std::endl;
        return;
    }

    std::cout << CYAN << "Введите начальный адрес (в шестнадцатеричном формате, например 0x1000) или оставьте пустым чтобы начать с самого начала: " << RESET;
    std::string start_address;
    std::cin.ignore();
    std::getline(std::cin, start_address);
    if (!start_address.empty()) {
        settings.start_address = std::stoull(start_address, nullptr, 16);
    } else {
        settings.start_address = 0;
    }

    std::cout << CYAN << "Введите начальный адрес диапазона (в шестнадцатеричном формате) или оставьте пустым для начала с начала: " << RESET;
    std::string address_range_start;
    std::getline(std::cin, address_range_start);
    if (!address_range_start.empty()) {
        settings.address_range_start = std::stoull(address_range_start, nullptr, 16);
    }

    std::cout << CYAN << "Введите конечный адрес диапазона (в шестнадцатеричном формате) или оставьте пустым для дизассемблирования до конца: " << RESET;
    std::string address_range_end;
    std::getline(std::cin, address_range_end);
    if (!address_range_end.empty()) {
        settings.address_range_end = std::stoull(address_range_end, nullptr, 16);
    }

    std::cout << CYAN << "Введите мнемоники для игнорирования (разделенные пробелом), например: add sub inc dec: " << RESET;
    std::string ignore;
    std::getline(std::cin, ignore);
    std::istringstream iss(ignore);
    for (std::string mnemonic; iss >> mnemonic; ) {
        settings.ignoreMnemonics.insert(mnemonic);
    }

    std::cout << CYAN << "Выводить байты инструкций? (y/n): " << RESET;
    std::string show_bytes;
    std::getline(std::cin, show_bytes);
    settings.show_bytes = (show_bytes == "y");

    std::cout << CYAN << "Выводить мнемоники инструкций? (y/n): " << RESET;
    std::string show_mnemonics;
    std::getline(std::cin, show_mnemonics);
    settings.show_mnemonics = (show_mnemonics == "y");

    std::cout << CYAN << "Выводить операнды инструкций? (y/n): " << RESET;
    std::string show_operands;
    std::getline(std::cin, show_operands);
    settings.show_operands = (show_operands == "y");

    std::cout << CYAN << "Введите путь к выходному файлу (оставьте пустым для вывода в консоль): " << RESET;
    std::getline(std::cin, settings.output_file);
}


void printFileInfo(const std::string &filePath) {
    std::cout << BLUE << "Информация о файле: " << filePath << RESET << std::endl;

    
    std::cout << "Размер файла: " << std::filesystem::file_size(filePath) << " байт" << std::endl;
   
}


bool isUrl(const std::string& source) {
    return source.find("http://") == 0 || source.find("https://") == 0;
}


std::vector<uint8_t> getBinaryData(const std::string& source) {
    if (isUrl(source)) {
        return downloadFile(source);
    } else {
        return readBinaryFile(source);
    }
}


void parseCommandLineArguments(int argc, char **argv, Settings &settings, std::string &filePath) {
    int opt;
    while ((opt = getopt(argc, argv, "f:s:e:o:bm")) != -1) {
        switch (opt) {
            case 'f':
                filePath = optarg;
                break;
            case 's':
                settings.start_address = std::stoull(optarg, nullptr, 16);
                break;
            case 'e':
                settings.address_range_end = std::stoull(optarg, nullptr, 16);
                break;
            case 'o':
                settings.output_file = optarg;
                break;
            case 'b':
                settings.show_bytes = true;
                break;
            case 'm':
                settings.show_mnemonics = true;
                break;
            default:
                std::cerr << RED << "Usage: " << argv[0] << " -f <file> -s <start_address> -e <end_address> -o <output_file> -b -m" << RESET << std::endl;
                exit(EXIT_FAILURE);
        }
    }

    if (filePath.empty()) {
        std::cerr << RED << "Input file is required. Use -f <file>." << RESET << std::endl;
        exit(EXIT_FAILURE);
    }

    if (!autoDetectArchitectureAndMode(filePath, settings)) {
        std::cerr << RED << "Failed to auto-detect architecture and mode" << RESET << std::endl;
        exit(EXIT_FAILURE);
    }
}

void generatePseudocode(const std::vector<cs_insn> &instructions) {
    std::cout << CYAN << "\nПримерный исходный код программы:\n" << RESET << std::endl;
    for (const auto &insn : instructions) {
        std::cout << GREEN << insn.mnemonic << " " << insn.op_str << RESET << " // " << getInstructionDescription(insn.mnemonic) << std::endl;
    }
}


void generateCFG(const std::vector<cs_insn> &instructions, const std::string &filename) {
    Agraph_t *g = agopen(const_cast<char*>("CFG"), Agdirected, nullptr);
    std::map<uint64_t, Agnode_t*> nodes;

    for (const auto &insn : instructions) {
        uint64_t addr = insn.address;
        char addrStr[20];
        snprintf(addrStr, sizeof(addrStr), "0x%llx", addr);
        
        if (nodes.find(addr) == nodes.end()) {
            nodes[addr] = agnode(g, addrStr, 1);
            agsafeset(nodes[addr], const_cast<char*>("label"), addrStr, const_cast<char*>(""));
        }

        if (strncmp(insn.mnemonic, "j", 1) == 0 || strcmp(insn.mnemonic, "call") == 0) {
            uint64_t target = std::strtoull(insn.op_str, nullptr, 0);
            snprintf(addrStr, sizeof(addrStr), "0x%llx", target);
            if (nodes.find(target) == nodes.end()) {
                nodes[target] = agnode(g, addrStr, 1);
                agsafeset(nodes[target], const_cast<char*>("label"), addrStr, const_cast<char*>(""));
            }
            agedge(g, nodes[addr], nodes[target], nullptr, 1);
        }
    }

    GVC_t *gvc = gvContext();
    gvLayout(gvc, g, "dot");
    gvRenderFilename(gvc, g, "png", filename.c_str());
    gvFreeLayout(gvc, g);
    agclose(g);
    gvFreeContext(gvc);
}

void generateDFG(const std::vector<cs_insn> &instructions, const std::string &filename) {
    Agraph_t *g = agopen(const_cast<char*>("DFG"), Agdirected, nullptr);
    std::map<uint64_t, Agnode_t*> nodes;

    for (const auto &insn : instructions) {
        uint64_t addr = insn.address;
        char addrStr[20];
        snprintf(addrStr, sizeof(addrStr), "0x%llx", addr);
        
        if (nodes.find(addr) == nodes.end()) {
            nodes[addr] = agnode(g, addrStr, 1);
            agsafeset(nodes[addr], const_cast<char*>("label"), addrStr, const_cast<char*>(""));
        }

        if (strncmp(insn.mnemonic, "mov", 3) == 0 || strncmp(insn.mnemonic, "lea", 3) == 0) {
            uint64_t target = std::strtoull(insn.op_str, nullptr, 0);
            snprintf(addrStr, sizeof(addrStr), "0x%llx", target);
            if (nodes.find(target) == nodes.end()) {
                nodes[target] = agnode(g, addrStr, 1);
                agsafeset(nodes[target], const_cast<char*>("label"), addrStr, const_cast<char*>(""));
            }
            agedge(g, nodes[addr], nodes[target], nullptr, 1);
        }
    }

    GVC_t *gvc = gvContext();
    gvLayout(gvc, g, "dot");
    gvRenderFilename(gvc, g, "png", filename.c_str());
    gvFreeLayout(gvc, g);
    agclose(g);
    gvFreeContext(gvc);
}

void analyzeDangerousInstructions(const std::vector<cs_insn> &instructions) {
    std::cout << RED << "\nАнализ опасных инструкций:\n" << RESET << std::endl;
    for (const auto &insn : instructions) {
        if (isInstructionDangerous(insn.mnemonic)) {
            std::cout << RED << insn.mnemonic << " " << insn.op_str << RESET << " // " << getInstructionDescription(insn.mnemonic) << std::endl;
        }
    }
}

void runProgramWithGDB(const std::string &filePath) {
    std::cout << CYAN << "Запуск программы с использованием GDB...\n" << RESET << std::endl;
    std::string command = "gdb -q -ex run -ex quit --args " + filePath;
    system(command.c_str());
}

int main(int argc, char** argv) {
    printBanner();
    printSupportedArchitectures();
    printSupportedModes();

    Settings settings;
    std::string filePath;

    if (argc > 1) {
        parseCommandLineArguments(argc, argv, settings, filePath);
    } else {
        getSettingsFromUser(settings, filePath);
    }

    printFileInfo(filePath);

   
    char runWithGDB;
    std::cout << CYAN << "Хотите запустить программу с использованием GDB перед дизассемблированием? (y/n): " << RESET;
    std::cin >> runWithGDB;
    if (runWithGDB == 'y' || runWithGDB == 'Y') {
        runProgramWithGDB(filePath);
    }

    std::vector<uint8_t> code = getBinaryData(filePath);
    if (code.empty()) {
        return 1;
    }

    std::vector<cs_insn> instructions;
    disassemble(code, settings, instructions);

    generatePseudocode(instructions);
    generateCFG(instructions, "cfg.png");
    generateDFG(instructions, "dfg.png");
    analyzeDangerousInstructions(instructions);

    return 0;
}
