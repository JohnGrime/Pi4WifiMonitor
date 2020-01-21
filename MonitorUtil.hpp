#if !defined(MONITOR_UTIL_DEFINED)
#define MONITOR_UTIL_DEFINED

#include <climits>
#include <vector>

#include <pcap/pcap.h>

namespace MonitorUtil
{
	using MACAddress = uint8_t[6];

	// Copy from pointer into data, increment pointer by size of data
	template<typename T>
	unsigned char const * ExtractAndAdvance(T *dst, unsigned char const * src)
	{
		memcpy(dst, src, sizeof(T));
		return src + sizeof(T);
	}

	// Arbitrary POD to binary string with optional number of binary digits
	template<typename T>
	char * ToString(const T &t, std::vector<char> &out, size_t Nb = 0)
	{
		size_t Nb_max = sizeof(T) * CHAR_BIT;
		Nb = (Nb==0) ? (Nb_max) : std::min(Nb, Nb_max);
		
		out.resize(Nb+1);
		out[Nb] = '\0';

		for (size_t i=0; i<Nb; i++) {
			T flag = 1 << ((Nb-1)-i);
			out[i] = ((t&flag) == flag) ? '1' : '0';
		}

		return &out[0];
	}

	// Explicit instantiation of ToString() for colon-separated MAC address
	template<>
	char * ToString(const MACAddress &addr, std::vector<char> &out, size_t)
	{
		out.resize(6*3);
		for (int i=0; i<6; i++) sprintf( &out[i*3], "%.2x%c", addr[i], i<5 ? ':' : '\0');

		return &out[0];
	}

	// http://www.radiotap.org/
	struct RadiotapHeader {
		uint8_t version;
		uint8_t padding;
		uint16_t length;
		std::vector<uint32_t> present;

		void Parse(unsigned char const *src)
		{
			uint32_t more = 1<<31;

			present.clear();

			src = ExtractAndAdvance(&version, src);
			src = ExtractAndAdvance(&padding, src);
			src = ExtractAndAdvance(&length,  src);

			while (true)
			{
				uint32_t temp;
				src = ExtractAndAdvance(&temp, src);
				present.push_back(temp);
				if ((temp&more) != more) break;
			}

			/*
			// Must parse following data in correct sequence!
			if (Has(TSFT_bit)) { src = ExtractAndAdvance(..., src);
			if (Has(Flags_bit)) { src = ExtractAndAdvance(..., src);
			... etc ...
			*/
		}

		// i == bit index; 0 <= i <= present.size()*32
		bool Has(int i)
		{
			size_t j = i/32;           // 32 bit word containing the flag
			uint32_t mask = 1<<(i%32); // mask for flag in appropriate word

			return (j>=present.size()) ? (false) : ((present[j]&mask) == mask);
		}
	};

	// 802.11
	struct FrameHeader {
		uint16_t control;
		uint16_t duration;
		MACAddress rcvAddr; // receiver
		MACAddress trnAddr; // transmitter
		MACAddress fltAddr; // can be used for filtering purposes

		enum class ControlMasks : uint16_t {
			Version = 0b0000000000000011,
			Type    = 0b0000000000001100,
			SubType = 0b0000000011110000,
		};

		enum class Types : uint16_t {
			Management = 0b000000000000'00'00,
			Control    = 0b000000000000'01'00,
			Data       = 0b000000000000'10'00,
		};

		enum class Subtypes : uint16_t {
			// Management subtypes
			AssocReq     = 0b00000000'0000'0000,
			AssocResp    = 0b00000000'0001'0000,
			ReassocReq   = 0b00000000'0010'0000,
			ReassocResp  = 0b00000000'0011'0000,
			ProbeReq     = 0b00000000'0100'0000,
			ProbeResp    = 0b00000000'0101'0000,
			Beacon       = 0b00000000'1000'0000,
			ATIM         = 0b00000000'1001'0000,
			Disassoc     = 0b00000000'1010'0000,
			Auth         = 0b00000000'1011'0000,
			Deauth       = 0b00000000'1100'0000,
			// Control subtypes
			PSPoll       = 0b00000000'1010'0000,
			RTS          = 0b00000000'1011'0000,
			CTS          = 0b00000000'1100'0000,
			ACK          = 0b00000000'1101'0000,
			CFEnd        = 0b00000000'1110'0000,
			CFEndCFAck   = 0b00000000'1111'0000,
			// Data subtypes
			Data            = 0b00000000'0000'0000,
			DataCFAck       = 0b00000000'0001'0000,
			DataCFPoll      = 0b00000000'0010'0000,
			DataCFAckCFPoll = 0b00000000'0011'0000,
			Null            = 0b00000000'0100'0000,
			CFAck           = 0b00000000'0101'0000,
			CFPoll          = 0b00000000'0110'0000,
			CFAckCFPoll     = 0b00000000'0111'0000,
		};

		void Parse(unsigned char const *src)
		{
			src = ExtractAndAdvance(&control,  src);
			src = ExtractAndAdvance(&duration, src);
			src = ExtractAndAdvance(&rcvAddr,  src);
			src = ExtractAndAdvance(&trnAddr,  src);
			src = ExtractAndAdvance(&fltAddr,  src);
		}

		static const char * ControlToString(uint16_t control)
		{
			using ST = Subtypes;

			auto t_mask = static_cast<uint16_t>(ControlMasks::Type);
			auto st_mask = static_cast<uint16_t>(ControlMasks::SubType);

			auto t = static_cast<Types>(control & t_mask);
			auto st = static_cast<Subtypes>(control & st_mask);

			if (t == Types::Management) {
				if      (st == ST::AssocReq)    return "Management:AssocReq";
				else if (st == ST::AssocResp)   return "Management:AssocResp";
				else if (st == ST::ReassocReq)  return "Management:ReassocReq";
				else if (st == ST::ReassocResp) return "Management:ReassocResp";
				else if (st == ST::ProbeReq)    return "Management:ProbeReq";
				else if (st == ST::ProbeResp)   return "Management:ProbeResp";
				else if (st == ST::Beacon)      return "Management:Beacon";
				else if (st == ST::ATIM)        return "Management:ATIM";
				else if (st == ST::Disassoc)    return "Management:Disassoc";
				else if (st == ST::Auth)        return "Management:Auth";
			}
			else if (t == Types::Control) {
				if      (st == ST::PSPoll)     return "Control:PSPoll";
				else if (st == ST::RTS)        return "Control:RTS";
				else if (st == ST::CTS)        return "Control:CTS";
				else if (st == ST::ACK)        return "Control:ACK";
				else if (st == ST::CFEnd)      return "Control:CFEnd";
				else if (st == ST::CFEndCFAck) return "Control:CFEndCFAck";
			}
			else if (t == Types::Data) {
				if      (st == ST::Data)            return "Data:Data";
				else if (st == ST::DataCFAck)       return "Data:DataCFAck";
				else if (st == ST::DataCFPoll)      return "Data:DataCFPoll";
				else if (st == ST::DataCFAckCFPoll) return "Data:DataCFAckCFPoll";
				else if (st == ST::Null)            return "Data:Null";
				else if (st == ST::CFAck)           return "Data:CFAck";
				else if (st == ST::CFPoll)          return "Data:CFPoll";
				else if (st == ST::CFAckCFPoll)     return "Data:CFAckCFPoll";
			}

			return "UNKNOWN";
		}
	};

}

#endif
