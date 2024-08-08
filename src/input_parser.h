#pragma once
#include "pch.h"
#include "argparse/argparse.hpp"


using ARGV = char **;
using Parser = argparse::ArgumentParser;

class InputParser
{
public:
    static std::tuple<int, std::string, std::vector<std::string>> GetInputParameters(int argc, ARGV& argv);
private:
    static void RegisterPid(Parser &parser);
    static void RegisterCommand(Parser &parser);
    static int GetPidValue(std::optional<int> pid);
    static std::optional<int> ExtractPid(Parser &parser);
    static void ApplyParser(Parser &parser, int argc, ARGV &argv);
    static std::optional<std::string> ExtractCommand(Parser &parser);
    static void CheckInputs(Parser &parser, std::optional<int> pid, std::optional<std::string> cmd);
    static std::tuple<std::string, std::vector<std::string>> separateCommandAndParams(std::optional<std::string> cmd);
};
