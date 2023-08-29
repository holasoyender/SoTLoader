#pragma once

#include "utils.h"
#include <yaml-cpp/yaml.h>

class Locale
{

private:
	std::string langCode;
	std::fstream file;
	YAML::Node node;

	void loadFile() {
		std::string path = "locale/" + langCode + ".yml";
		file.open(path, std::ios::in);
		if (!file.is_open()) {
			logger::error("Failed to open file: ", path, ". Defaulting to en.yml");
			file.open("locale/en.yml", std::ios::in);
			if (!file.is_open()) {
				logger::error("Failed to open file: locale/en.yml");
				system("pause");
				exit(1);
			}
		}
	}

public:
	Locale(std::string langCode)
	{
		this->langCode = langCode;

		loadFile();

		try {
			node = YAML::Load(file);
		}
		catch (const std::runtime_error& re)
		{
			logger::error("Runtime error when loading lang file: ", re.what());
			system("pause");
			exit(1);
		}
		catch (const std::exception& ex)
		{
			logger::error("Error occurred: ", ex.what());
			system("pause");
			exit(1);
		}
		catch (...)
		{
			logger::error("Unknown failure occurred. Possible memory corruption");
			system("pause");
			exit(1);
		}
	}

	std::string get(const std::string& key, std::string default_value = "Unknown string") {
		try {
			return node[key].as<std::string>();
		}
		catch (const std::runtime_error& re)
		{
			logger::error("Runtime error when getting string: ", re.what());
		}
		catch (const std::exception& ex)
		{
			logger::error("Error occurred when getting string: ", ex.what());
		}
		catch (...)
		{
			logger::error("Unknown failure occurred when getting string. Possible memory corruption");
		}
		return default_value;
	}

};