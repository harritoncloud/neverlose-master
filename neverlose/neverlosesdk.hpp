/*
	This is what you think.
*/
#ifndef NEVERLOSE_SDK_HPP
#define NEVERLOSE_SDK_HPP
#include <cstdint>
#include <string>
#include "json.hpp"

namespace neverlosesdk
{
	namespace network
	{
		class Requestor
		{
			virtual void MakeRequest(std::string& out, std::string_view route, int, int) = 0;
			virtual void GetSerial(std::string& out, nlohmann::json& request) = 0;
			virtual void fn2() = 0;
			// fn3 is the WebSocket data handler - same signature as GetSerial
			// Called for: config fetches (type 0), heartbeat (type 1), skin data (type 2),
			//             entity/netvar data (type 3), auth (type 4), lua scripts (type 5)
			virtual void fn3(std::string& out, nlohmann::json& request) = 0;
			virtual void QueryLuaLibrary(std::string& out, std::string_view name) = 0;
		};

		class Client
		{
			virtual void vt() = 0;

			int IsConnected;
			void* endpoint; // websocketpp object
			uint32_t resrved[0x2];
			char* SomeKey; // Message from auth
			uint32_t resrved2[0x6];
			char* SomeKey1; // Data from auth
		};
	};

	namespace gui
	{
		class Menu
		{
		public:
			char pad0[0x4];
			bool IsOpen;
			char pad1[0x3];
			float Alpha;
			int IsEditingStyle; // normaly -1, when edit style popup visible turns 0
			char pad2[0x8];
		};
	};
};

#endif // NEVERLOSE_SDK_HPP