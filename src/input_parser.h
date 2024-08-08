#pragma once
#include "pch.h"
#include "argparse/argparse.hpp"


using ARGV = char **;
using Parser = argparse::ArgumentParser;

class InputParser
{
public:
    static std::tuple<int, std::string, std::vector<std::string>> get_input_parameters(int argc, ARGV& argv);
private:
    static void register_pid(Parser &parser);
    static void register_command(Parser &parser);
    static int get_pid_value(std::optional<int> pid);
    static std::optional<int> extract_pid(Parser &parser);
    static void apply_parser(Parser &parser, int argc, ARGV &argv);
    static std::optional<std::string> extract_command(Parser &parser);
    static void check_inputs(Parser &parser, std::optional<int> pid, std::optional<std::string> cmd);
    static std::tuple<std::string, std::vector<std::string>> separate_command_params(std::optional<std::string> cmd);
};
