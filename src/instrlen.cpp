/*
 *  Change the length of current instruction
 *
 *
 */

#include <auto.hpp>
#include <bytes.hpp>
#include <ida.hpp>
#include <idp.hpp>
#include <kernwin.hpp>
#include <loader.hpp>
#include <segregs.hpp>

const char *const cref_to_str(uchar cr)
{
	switch (cr)
	{
	case fl_U:
		return "fl_U";
	case fl_CF:
		return "fl_CF";
	case fl_CN:
		return "fl_CN";
	case fl_JF:
		return "fl_JF";
	case fl_JN:
		return "fl_JN";
	case fl_USobsolete:
		return "fl_USobsolete";
	case fl_F:
		return "fl_F";
	default:
		return "unknown";
	}
}

struct instruction_resizer_t : public plugmod_t, public post_event_visitor_t
{
	netnode new_sizes = netnode("$ instruction new sizes", 0, true);
	netnode original_sizes = netnode("$ instruction original sizes", 0, true);

	instruction_resizer_t()
	{
		register_post_event_visitor(HT_IDP, this, this);

		// dump all new sizes
	}

	void dump_sizes()
	{
		qstring name;

		msg("new sizes:\n");
		new_sizes.get_name(&name);
		msg("new sizes name: %s\n", name.c_str());
		for (ea_t ea = new_sizes.altfirst(); ea != BADADDR; ea = new_sizes.altnext(ea))
		{
			msg("\tnew size at %llx is %llx\n", ea, new_sizes.altval_ea(ea));
		}
		// dump all original sizes
		msg("original sizes:\n");
		original_sizes.get_name(&name);
		msg("original sizes name: %s\n", name.c_str());
		for (ea_t ea = original_sizes.altfirst(); ea != BADADDR; ea = original_sizes.altnext(ea))
		{
			msg("\toriginal size at %llx is %llx\n", ea, original_sizes.altval_ea(ea));
		}
	}

	~instruction_resizer_t()
	{
		unregister_post_event_visitor(HT_IDP, this);
	}

	virtual bool idaapi run(size_t arg) override;

	virtual ssize_t idaapi handle_post_event(ssize_t code, int notification_code, va_list va) override;
};

ssize_t idaapi instruction_resizer_t::handle_post_event(ssize_t retcode, int notification_code, va_list va)
{
	switch (notification_code)
	{
	case processor_t::ev_ana_insn:
		///< Analyze one instruction and fill 'out' structure.
		///< This function shouldn't change the database, flags or anything else.
		///< All these actions should be performed only by emu_insn() function.
		///< \insn_t{ea} contains address of instruction to analyze.
		///< \param out           (::insn_t *)
		///< \return length of the instruction in bytes, 0 if instruction can't be decoded.
		///< \retval 0 if instruction can't be decoded.:
		{
			insn_t *insn = va_arg(va, insn_t *);
			if (insn && (retcode > 0))
			{
				auto new_size = new_sizes.altval_ea(insn->ea);
				if (!new_size)
					break;

				msg("shortening instruction at %llx to %llu\n", insn->ea, new_size);
				original_sizes.altset_ea(insn->ea, insn->size);
				insn->size = new_size;

				for (int i = 0; i < 8; ++i)
					insn->ops[i].offb = 0;
				return insn->size;
			}
		}
		break;

	case processor_t::ev_emu_insn:
	{

		///< Emulate instruction, create cross-references, plan to analyze
		///< subsequent instructions, modify flags etc. Upon entrance to this function,
		///< subsequent instructions, modify flags etc. Upon entrance to this function,
		///< all information about the instruction is in 'insn' structure.
		///< \param insn          (const ::insn_t *)
		///< \retval  1 ok
		///< \retval -1 the kernel will delete the instruction

		insn_t *insn = va_arg(va, insn_t *);

		if (insn && (retcode == 1))
		{

			auto new_size = new_sizes.altval_ea(insn->ea);
			if (!new_size)
				break;

			auto orig_size = original_sizes.altval_ea(insn->ea);
			if (orig_size == 0)
			{
				msg("no orig size of instr at %llx\n", insn->ea);
				break;
			}

			// ida most likely created a flow from the original instruction to the new one
			// we need to remove it

			bool del_flow = false;
			// print all crefs from current instruction
			auto ea_original_flow = insn->ea + orig_size;
			auto ea_new_flow = insn->ea + new_size;
			if (1)
			{
				msg("crefs from %llx\n", insn->ea);
				auto i = 0;
				/*for (auto ea = get_first_cref_from(insn->ea); ea != BADADDR; ea = get_next_cref_from(insn->ea, ea))
				{
					msg("%d. cref from %llx to %llx\n", i++, insn->ea, ea);
				}*/
				xrefblk_t xb;
				for (bool ok = xb.first_from(insn->ea, XREF_ALL); ok; ok = xb.next_from())
				{
					// xb.to - contains the referenced address
					msg("%d. cref from %llx to %llx type: %d = %s user: %d iscode: %d\n", i++, xb.from, xb.to, xb.type, cref_to_str(xb.type), xb.user, xb.iscode);
					if (xb.type == fl_F && xb.to == ea_new_flow)
					{
						del_flow = true;
					}
				}
			}

			// msg("fixing crefs instruction at %x to %d -> %d\n", insn->ea, new_size, orig_size);

			// TODO: check whethere this flow exists
			if (del_flow)
			{
				del_cref(insn->ea, ea_new_flow, false);

				// add flow to the original "next" instruction
				auto ok3 = add_cref(insn->ea, ea_original_flow, fl_JN);
				if (!ok3)
					msg("failed to add fl_F cref from %llx to %llx\n", insn->ea, ea_original_flow);
			}

			if (0)
			{
				
				if (!is_head(get_flags(ea_original_flow)))
				{
					ea_t ea_1 = get_item_head(ea_original_flow);

					msg("[!] %llx's destination is inside instruction at %llx at %llx. Fixing...\n", insn->ea, ea_1, ea_original_flow);
					// new_sizes.altset_ea(ea_1, ea_original_flow - ea_1);
					// plan_ea(ea_1);
				}
			}
		}
	}
	break;
	}
	return retcode;
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
	plugmod_t *result = new instruction_resizer_t();
	
	// Register addon with IDA
	addon_info_t addon;
	addon.id = "milankovo.instrlen";
	addon.name = "Change Instruction Length";
	addon.producer = "Milankovo";
	addon.url = "https://github.com/milankovo/instrlen";
	addon.version = "1.0.2";
	register_addon(&addon);
	
	return result;
}

//--------------------------------------------------------------------------
static const char comment[] = "Change the callee address";
static const char help[] =
	"This plugin allows the user to change the length of the current instruction\n";

//--------------------------------------------------------------------------
static const char *const form =
	"HELP\n"
	"%s\n"
	"ENDHELP\n"
	"Enter the new length\n"
	"\n"
	"  <~N~ew length:L::40:::>\n"
	"\n"
	"\n";

bool idaapi instruction_resizer_t::run(size_t)
{
	ea_t ea = get_screen_ea(); // get current address
	if (!is_code(get_flags(ea)))
		return false; // not an instruction
					  // get the callee address from the database
	// ea_t callee = node2ea(n.altval_ea(ea) - 1);

	ea_t size = new_sizes.altval_ea(ea);

	if (size == 0)
		size = get_item_size(ea);

	char buf[MAXSTR];
	qsnprintf(buf, sizeof(buf), form, help);
	if (ask_form(buf, &size) > 0)
	{
		if (size == BADADDR)
		{
			// msg("removing new size for instr at %llx", ea);
			new_sizes.altdel_ea(ea);
			original_sizes.altdel_ea(ea);
		}
		else
		{
			msg("setting the new size of instruction at %llx to %llx\n", ea, size);
			new_sizes.altset_ea(ea, size);
			// original_sizes.altdel_ea(ea);
		}
		plan_ea(ea); // reanalyze the current instruction
	}
	else
	{
		// msg("ask form failed\n");
	}

	return true;
}

//--------------------------------------------------------------------------
static const char wanted_name[] = "Change instruction length";
static const char wanted_hotkey[] = "Alt-F12";

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
	{
		IDP_INTERFACE_VERSION,
		PLUGIN_MULTI, // plugin flags
		init,		  // initialize

		nullptr, // terminate. this pointer may be nullptr.
		nullptr, // invoke plugin

		comment, // long comment about the plugin
				 // it could appear in the status line
				 // or as a hint

		help, // multiline help about the plugin

		wanted_name,  // the preferred short name of the plugin
		wanted_hotkey // the preferred hotkey to run the plugin
};
