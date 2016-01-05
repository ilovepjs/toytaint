/*--------------------------------------------------------------------*/
/*--- Toytaint           		                 tt_main.c ---*/
/*--------------------------------------------------------------------*/

/*
   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307, USA.

   The GNU General Public License is contained in the file COPYING.
*/

#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_debuginfo.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_options.h"
#include "pub_tool_xarray.h"      // VG_(*XA) 
#include "pub_tool_wordfm.h"      // VG_(*FM) 
#include "pub_tool_machine.h"     // VG_(fnptr_to_fnentry)
#include "copy.c"

#include "toytaint.h"

#define KRED "\e[31m"
#define KNRM "\e[0m"

/*------------------------------------------------------------*/
/*--- Stuff for --trace-mem                                ---*/
/*------------------------------------------------------------*/

#define MAX_DSIZE    512

typedef 
   enum { Event_Load, Event_Store, Event_Op }
   EventKind;

static XArray* tainted;
static WordFM* kvStore;

static Addr taint = NULL;

static Int cmp_tainted_by_reg(const void* v1, const void* v2);
static Word cmp_key_by_reg(UWord v1, UWord v2);
static Bool spreadTaint(IRExpr* expr);

static VG_REGPARM(2) void trace_load(Addr addr, SizeT size, IRStmt *expr)
{
   if (addr == taint || spreadTaint(expr->Ist.WrTmp.data)) {
      IRExpr* dest = IRExpr_RdTmp(expr->Ist.WrTmp.tmp);
      VG_(addToXA)(tainted, dest);
      VG_(printf)("TAINTED: ");
      ppIRStmt(expr);
      VG_(printf)("\n");
   } 
}

static VG_REGPARM(3) void trace_op(IRStmt *expr, UInt one, UInt two)
{
   if (spreadTaint(expr->Ist.WrTmp.data)) {
      IRExpr* dest = IRExpr_RdTmp(expr->Ist.WrTmp.tmp);
      VG_(addToXA)(tainted, dest);
      VG_(printf)("TAINTED: ");
      ppIRStmt(expr);
      VG_(printf)("\n");
   } 
}

static VG_REGPARM(2) void trace_store(Addr addr, SizeT size, IRStmt *expr, Addr last)
{
   if (addr == taint) {
      taint = 1;
   } else if (spreadTaint(expr->Ist.Store.data)) {
      IRExpr* val = NULL;
      if (VG_(lookupFM)(kvStore, NULL, (UWord*)&val,expr->Ist.Store.addr->Iex.RdTmp.tmp)) {
         VG_(sortXA)(tainted);
         VG_(addToXA)(tainted, val);
         VG_(printf)("TAINTED: ");
         ppIRStmt(expr);
         VG_(printf)("\n");
      } 
   }
}

static void mkCall(IRSB* sb, EventKind ev, IRStmt* stmt, IRExpr* addr)
{
   const HChar* helperName;
   void*      helperAddr;
   IRExpr**   argv = NULL;
   IRDirty*   di = NULL;

   // Decide on helper fn to call and args to pass it.
   switch (ev) {
      case Event_Load:  helperName = "trace_load";
                        helperAddr =  trace_load;   break;

      case Event_Store: helperName = "trace_store";
                        helperAddr =  trace_store;  break;

      case Event_Op:    helperName = "trace_op";
                        helperAddr =  trace_op;
                        argv = mkIRExprVec_3( mkIRExpr_HWord( (HWord) stmt),
                                              mkIRExpr_HWord( 1),
                                              mkIRExpr_HWord( 2));
                        di   = unsafeIRDirty_0_N(3, helperName, 
                                  VG_(fnptr_to_fnentry)( helperAddr ), argv );
                        break;

      default:
         tl_assert(0);
   }

   if (!di || !argv) {
      // Add the helper.
      argv = mkIRExprVec_3(addr, mkIRExpr_HWord( 0), mkIRExpr_HWord((HWord) stmt));
      di   = unsafeIRDirty_0_N( 2, helperName, 
                                   VG_(fnptr_to_fnentry)( helperAddr ), argv );
   }

   IRStmt* a = IRStmt_Dirty(di);
   addStmtToIRSB( sb, a);
}

/*------------------------------------------------------------*/
/*--- Basic tool functions                                 ---*/
/*------------------------------------------------------------*/

static void tt_post_clo_init(void)
{
}

static
IRSB* tt_instrument ( VgCallbackClosure* closure,
                      IRSB* bb,
                      const VexGuestLayout* layout, 
                      const VexGuestExtents* vge,
                      const VexArchInfo* archinfo_host,
                      IRType gWordTy, IRType hWordTy )
{
   Int        i;
   IRSB*      sbOut;
   IRTypeEnv* tyenv = bb->tyenv;

   if (gWordTy != hWordTy) {
      /* We don't currently support this case. */
      VG_(tool_panic)("host/guest word size mismatch");
   }

   /* Set up SB */
   sbOut = deepCopyIRSBExceptStmts(bb);

   //Move to a init data structures helgrind/hg_main
   tainted = 
      VG_(newXA)(VG_(malloc), "tt_tainted", VG_(free), sizeof(IRExpr));
   VG_(setCmpFnXA)(tainted, cmp_tainted_by_reg);

   kvStore =
      VG_(newFM)(VG_(malloc), "ss_kvstore", VG_(free), cmp_key_by_reg);

   // Copy verbatim any IR preamble preceding the first IMark
   i = 0;
   while (i < bb->stmts_used && bb->stmts[i]->tag != Ist_IMark) {
      addStmtToIRSB( sbOut, bb->stmts[i] );
      i++;
   }

   // Make sure no temp writes in the un instrumented preamble
   for (int j=0; j<i; j++) {
      if (bb->stmts[j]->tag == Ist_WrTmp) {
         VG_(tool_panic)("Wrote to a temporary");
      }
   }

   tl_assert(bb->stmts[i]->tag == Ist_IMark);

   // Iterate over remaining stmts
   for (/*use current i*/; i < bb->stmts_used; i++) {
      IRStmt* st = bb->stmts[i];
      IRStmt* clone = deepMallocIRStmt(st);

      if (!st || st->tag == Ist_NoOp) continue;

      if (0) {
         ppIRStmt(st);
         VG_(printf)("\n");
      }

      switch (st->tag) {
         case Ist_WrTmp: {
            IRExpr* data = st->Ist.WrTmp.data;
            VG_(addToFM)(kvStore, st->Ist.WrTmp.tmp, (UWord) data);
            switch (data->tag) {
               case Iex_Load:
                  mkCall(sbOut, Event_Load, clone, data->Iex.Load.addr);
                  break;
               case Iex_Binop:
               case Iex_Unop:
                  mkCall(sbOut, Event_Op, clone, NULL);
                  break;
               default:
                  break;
                  VG_(tool_panic)("Unfinished");
            }
            addStmtToIRSB( sbOut, st );
            break;
         }

         case Ist_Store: {
            IRType  type = typeOfIRExpr(tyenv, st->Ist.Store.data);
            tl_assert(type != Ity_INVALID);
            mkCall(sbOut, Event_Store, clone, st->Ist.Store.addr);
            addStmtToIRSB( sbOut, st );
            break;
         }

         default:
            addStmtToIRSB( sbOut, st );
      }
   }

   return sbOut;
}

static void tt_fini(Int exitcode)
{
}

static void tt_pre_syscall(ThreadId tid, UInt syscallno,
                           UWord* args, UInt nArgs)
{
}

static void tt_post_syscall(ThreadId tid, UInt syscallno,
                            UWord* args, UInt nArgs, SysRes res)
{
}

static void tt_make_mem_tainted(Addr a, SizeT len)
{
   taint = a;
   VG_(printf)("Tainting mem at %08lx.\n", a);
}

static void tt_make_mem_untainted(Addr a, SizeT len)
{
   taint = NULL;
   VG_(deleteXA)(tainted);
   tainted = 
      VG_(newXA)(VG_(malloc), "ss_tainted", VG_(free), sizeof(IRExpr));
   VG_(setCmpFnXA)(tainted, cmp_tainted_by_reg);
   VG_(printf)("Untainting mem at %08lx.\n", a);
}

static Bool tt_handle_client_requests(ThreadId tid, UWord* arg, UWord* ret)
{
   switch (arg[0])
   {
      case VG_USERREQ__TOYTAINT_MAKE_MEM_TAINTED:
         tt_make_mem_tainted(arg[1], arg[2]);
         break;
      case VG_USERREQ__TOYTAINT_MAKE_MEM_UNTAINTED:
         tt_make_mem_untainted(arg[1], arg[2]);
         break;
   }
   return True;
}

static void tt_pre_clo_init(void)
{
   VG_(details_name)            ("ToyTaint");
   VG_(details_version)         (0);
   VG_(details_description)     ("Taint Analysis");
   VG_(details_copyright_author)("");
   VG_(details_bug_reports_to)  (VG_BUGS_TO);

   VG_(details_avg_translation_sizeB) ( 275 );

   VG_(basic_tool_funcs)        (tt_post_clo_init,
                                 tt_instrument,
                                 tt_fini);


   VG_(needs_client_requests) (tt_handle_client_requests);

   /* No needs, no core events to track */
   VG_(needs_syscall_wrapper)	(tt_pre_syscall,
                                 tt_post_syscall);
}

VG_DETERMINE_INTERFACE_VERSION(tt_pre_clo_init)

/*--------------------------------------------------------------------*/
/*--- helper cmp functions                                         ---*/
/*--------------------------------------------------------------------*/

static Int cmp_tainted_by_reg(const void* v1, const void* v2) {
   const IRExpr* i1 = (const IRExpr*) v1;
   const IRExpr* i2 = (const IRExpr*) v2;

   if (i1->tag != i2->tag) {
      return i1->tag < i2->tag ? -1 : 1;
   }

   switch (i1->tag) {
      case Iex_RdTmp:
         if (i1->Iex.RdTmp.tmp < i2->Iex.RdTmp.tmp) return -1;
         if (i1->Iex.RdTmp.tmp > i2->Iex.RdTmp.tmp) return 1;
         return 0;
      case Iex_Binop: {
         Int left = cmp_tainted_by_reg(i1->Iex.Binop.arg1,
                                       i2->Iex.Binop.arg1);
         if (left != 0) return left;
         Int right = cmp_tainted_by_reg(i1->Iex.Binop.arg2,
                                       i2->Iex.Binop.arg2);
         if (right != 0) return right;
         return 0;
      }
      case Iex_Const: {
         Int t1 = i1->Iex.Const.con->tag;  
         Int t2 = i2->Iex.Const.con->tag;  
         if (t1 < t2) return -1;
         if (t1 > t2) return 1;
 
         switch (t1) {
            case Ico_U64: 
               if (i1->Iex.Const.con->Ico.U64 < 
                   i2->Iex.Const.con->Ico.U64) return -1;
               if (i1->Iex.Const.con->Ico.U64 > 
                   i2->Iex.Const.con->Ico.U64) return 1;
               return 0;
            case Ico_U32: 
               if (i1->Iex.Const.con->Ico.U32 < 
                   i2->Iex.Const.con->Ico.U32) return -1;
               if (i1->Iex.Const.con->Ico.U32 > 
                   i2->Iex.Const.con->Ico.U32) return 1;
               return 0;
            case Ico_U16: 
               if (i1->Iex.Const.con->Ico.U16 < 
                   i2->Iex.Const.con->Ico.U16) return -1;
               if (i1->Iex.Const.con->Ico.U16 > 
                   i2->Iex.Const.con->Ico.U16) return 1;
               return 0;
            case Ico_U8: 
               if (i1->Iex.Const.con->Ico.U8 < 
                   i2->Iex.Const.con->Ico.U8) return -1;
               if (i1->Iex.Const.con->Ico.U8 > 
                   i2->Iex.Const.con->Ico.U8) return 1;
               return 0;
            default:
               ppIRExpr(i1);
               VG_(printf)(" was not handled\n");
               VG_(tool_panic)("`cmp_tainted_by_reg - Const`");
         }
      }
      default:
         ppIRExpr(i1);
         VG_(printf)(" was not handled\n");
         VG_(tool_panic)("`cmp_tainted_by_reg`");
   }

   VG_(tool_panic)("`cmp_tainted_by_reg`");
   return 0;
}

static Word cmp_key_by_reg(UWord v1, UWord v2) {
   if (v1 < v2) return -1;
   if (v1 > v2) return 1;
   return 0;
}

static Bool spreadTaint(IRExpr* expr)
{
   switch (expr->tag) {
      case Iex_Binder:
         return False;
      case Iex_Const: 
         return False;
      case Iex_Get:
         return True;
      case Iex_GetI:
         return spreadTaint(expr->Iex.GetI.ix);
      case Iex_Qop: {
         IRQop* qop = expr->Iex.Qop.details;
         return spreadTaint(qop->arg1) ||
                spreadTaint(qop->arg2) ||
                spreadTaint(qop->arg3) ||
                spreadTaint(qop->arg4);
      }
      case Iex_Triop: {
         IRTriop* triop = expr->Iex.Triop.details;
         return spreadTaint(triop->arg1) ||
                spreadTaint(triop->arg2) ||
                spreadTaint(triop->arg3);
      }
      case Iex_Binop: {
         return spreadTaint(expr->Iex.Binop.arg1) ||
                spreadTaint(expr->Iex.Binop.arg2); 
      } 
      case Iex_Unop:
         return spreadTaint(expr->Iex.Unop.arg);
      case Iex_Load: 
         return spreadTaint(expr->Iex.Load.addr); 
      case Iex_CCall: {
         Bool furtherSpreadTaint = False;
         for (int i=0; expr->Iex.CCall.args[i]; i++) {
            furtherSpreadTaint |= spreadTaint(expr->Iex.CCall.args[i]);
         } 
         return furtherSpreadTaint;
      }
      case Iex_ITE:
         return spreadTaint(expr->Iex.ITE.iftrue) ||
                spreadTaint(expr->Iex.ITE.iffalse);
      case Iex_RdTmp: {
         VG_(sortXA)(tainted);
         return VG_(lookupXA)(tainted, expr, NULL, NULL);
      }
      default:
         VG_(tool_panic)("eof: spreadTaint");
   }
   VG_(tool_panic)("eof: spreadTaint");
   return False; 
}

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
